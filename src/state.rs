use std::{sync::Arc, time::Duration};

use crate::{
    admin::AdminAuthenticator,
    audit::AuditService,
    auth_factors::service::AuthFactorService,
    auth_limiter::{AuthFailureLimiter, RedisAuthFailureLimiter},
    clients::service::ClientService,
    clock::SharedClock,
    config::Config,
    consents::ConsentService,
    db::Database,
    keys::{KeyManager, KeyManagerError},
    oauth::providers::{
        endpoint_policy::EndpointPolicy, secrets::SecretManager, service::ExternalOAuthService,
        state_store::ExternalLoginStateStore,
    },
    oauth::quota::OAuthQuotaStore,
    oauth::rate_limit::QpsRateLimiter,
    oauth::refresh_store::RefreshTokenStore,
    oauth::request_store::AuthorizationRequestStore,
    oauth::revocation::TokenRevocationStore,
    oauth::store::AuthorizationCodeStore,
    plans::service::PlanService,
    redis_client::RedisClient,
    sessions::store::SessionStore,
    settings::{IssuerRuntime, SecurityLimitsSetting, SettingsService, issuer::IssuerRecord},
    users::service::UserService,
    web_dist::{WebDistError, WebDistRoot},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    /// 运行期 OIDC Issuer 的唯一权威。路由 middleware 在请求入口取得完整快照并放入
    /// request extensions，协议 handler 在整个请求内只使用那一份 generation。
    pub issuer: IssuerRuntime,
    /// 所有生命周期判定的时间来源。
    ///
    /// 这一个句柄被克隆给授权码 / Refresh Token / Session / MFA / 套餐 / 审计，
    /// 因此一次请求内的全部过期判定看到同一个「现在」。测试用
    /// [`AppState::with_clock`] 换成固定时钟，即可把到期边界推到两侧而不必真实
    /// 等待。
    ///
    /// 不覆盖的时间来源：Redis Lua 里的 `TIME`（限流 / State / 授权请求存储需要
    /// 跨实例一致）、SQL 里的 `NOW()`（事务时间）、`key_lock` 的文件 mtime。
    pub clock: SharedClock,
    /// 启动期已校验的前端产物根：静态文件服务的唯一来源（Issue #303）。
    pub web_dist: WebDistRoot,
    pub database: Database,
    pub redis: RedisClient,
    pub sessions: SessionStore,
    pub settings: SettingsService,
    pub users: UserService,
    pub clients: ClientService,
    pub keys: KeyManager,
    pub authorization_codes: AuthorizationCodeStore,
    pub refresh_tokens: RefreshTokenStore,
    pub authorization_requests: AuthorizationRequestStore,
    pub consents: ConsentService,
    pub revocations: TokenRevocationStore,
    pub oauth_quotas: OAuthQuotaStore,
    pub qps: QpsRateLimiter,
    pub plans: PlanService,
    pub admin: AdminAuthenticator,
    pub audit: AuditService,
    pub factors: AuthFactorService,
    pub external_oauth: ExternalOAuthService,
    pub external_login_states: ExternalLoginStateStore,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("application configuration is invalid: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("static asset configuration is invalid: {0}")]
    WebDist(#[from] WebDistError),
    #[error("database configuration is invalid: {0}")]
    Database(#[from] crate::db::DbError),
    #[error("issuer configuration could not be resolved: {0}")]
    Issuer(#[from] crate::settings::IssuerSettingError),
    #[error("redis configuration is invalid: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("key manager initialization failed: {0}")]
    Keys(#[from] KeyManagerError),
    #[error("external OAuth initialization failed: {0}")]
    ExternalOAuth(#[from] crate::oauth::providers::service::ExternalOAuthError),
    #[error("external OAuth secret initialization failed: {0}")]
    ExternalOAuthSecret(#[from] crate::oauth::providers::secrets::SecretError),
    /// 静态根校验与密钥加载都放在阻塞线程池执行，线程 panic 或被取消时只能观察到
    /// JoinError。保留这个变体而不是 unwrap，启动失败时才不会丢掉真实原因。
    #[error("startup blocking task failed: {0}")]
    StartupTask(#[from] tokio::task::JoinError),
}

/// 启动阶段一次性加载的密钥材料。
///
/// `KeyManager` 与 `SecretManager` 都直接读写 `KEY_DIRECTORY` 下的文件，缺失时
/// 还会生成材料。两者使用互不重叠的临时文件前缀，各自只清理自己的半成品，避免
/// 一方正在写的 `.tmp` 被另一方当成崩溃残留删掉。打包成一个结构体是为了只做一次
/// `spawn_blocking` 往返，而不是每个密钥各跨一次线程。
struct StartupKeyMaterial {
    keys: KeyManager,
    secrets: SecretManager,
}

impl StartupKeyMaterial {
    /// 同步加载全部密钥材料，只允许在 `spawn_blocking` 的阻塞线程里调用。
    fn load(
        key_directory: &str,
        key_retention: Duration,
        key_skew_allowance: Duration,
        key_activation_delay: Duration,
    ) -> Result<Self, StateError> {
        // 保持与历史实现一致的失败顺序：先 provider secret，再签名密钥。
        let secrets = SecretManager::load_or_generate(key_directory)?;
        let keys = KeyManager::load_or_generate_with_lifecycle(
            key_directory,
            key_retention,
            key_skew_allowance,
            key_activation_delay,
        )?;
        Ok(Self { keys, secrets })
    }
}

impl AppState {
    /// 使用懒加载数据库池构建状态，保留请求期报告数据库故障的既有语义。
    pub async fn new(config: Config) -> Result<Self, StateError> {
        let database = crate::db::connect(&config)?;
        Self::new_with_pool(config, database).await
    }

    /// 生产启动路径：监听前解析持久化 Issuer，不改变 [`Self::new`] 的懒加载语义。
    pub async fn new_with_persisted_issuer(mut config: Config) -> Result<Self, StateError> {
        let database = crate::db::connect(&config)?;
        let raw = crate::settings::issuer::load_raw(&database).await?;
        let issuer = if raw.as_ref().is_some_and(|record| {
            record
                .value
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        }) {
            // A row with an empty value is persisted state, not bootstrap absence.
            config.issuer = None;
            IssuerRuntime::new_from_raw(&config, raw.as_ref())
        } else {
            match crate::settings::issuer::resolve(&mut config, &database).await {
                Ok(Some(record)) => IssuerRuntime::new(&config, Some(&record))?,
                Ok(None) => {
                    let raw = crate::settings::issuer::load_raw(&database).await?;
                    IssuerRuntime::new_from_raw(&config, raw.as_ref())
                }
                Err(crate::settings::IssuerSettingError::Invalid(_)) => {
                    let generation = crate::settings::issuer::load_raw(&database)
                        .await?
                        .map(|record| record.generation)
                        .unwrap_or_default();
                    IssuerRuntime::new_invalid(&config, generation)
                }
                Err(error) => return Err(error.into()),
            }
        };
        Self::new_with_pool_and_issuer(config, database, issuer).await
    }

    /// 用另一个时钟重建全部时间敏感的 store 与 service。
    ///
    /// 必须重建而不是只替换 `self.clock`：store 在构造时各自克隆了一份句柄，
    /// 单改字段会留下一半旧时钟，正是那种"看起来注入了、实际没生效"的假象。
    ///
    /// 用途是集成测试：先用 `new_with_pool` 建好状态，再换成固定时钟驱动
    /// 授权码、Refresh Token、Session 和 MFA 的到期边界。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.authorization_codes = self.authorization_codes.clone().with_clock(clock.clone());
        self.refresh_tokens = self.refresh_tokens.clone().with_clock(clock.clone());
        // ClientService 持有一份用于 secret 轮换撤销的 RefreshTokenStore 克隆，
        // 必须同步替换，否则轮换路径仍读旧时钟。
        self.clients = self
            .clients
            .clone()
            .with_refresh_tokens(self.refresh_tokens.clone());
        self.sessions = self.sessions.clone().with_clock(clock.clone());
        self.factors = self.factors.clone().with_clock(clock.clone());
        self.plans = self.plans.clone().with_clock(clock.clone());
        self.audit = self.audit.clone().with_clock(clock.clone());
        self.clock = clock;
        self
    }

    /// 使用外部提供的数据库连接池构建 AppState，不再内部调用 `db::connect`。
    ///
    /// 主要用途：测试中传入 schema 隔离的 pool（见 `tests/support/db_isolation.rs`），
    /// 保证应用层与测试层共用同一个 pool（相同的 `search_path` / schema）。
    ///
    /// 生产路径额外解析持久化 Issuer；测试可使用 `new` 或传入隔离 pool。
    pub async fn new_with_pool(
        config: Config,
        database: crate::db::Database,
    ) -> Result<Self, StateError> {
        let issuer = match config.issuer.as_ref() {
            Some(issuer) => IssuerRuntime::new(
                &config,
                Some(&IssuerRecord {
                    value: issuer.as_str().to_owned(),
                    generation: 1,
                    updated_at: time::OffsetDateTime::now_utc(),
                }),
            )?,
            None => IssuerRuntime::new_from_raw(&config, None),
        };
        Self::new_with_pool_and_issuer(config, database, issuer).await
    }

    async fn new_with_pool_and_issuer(
        config: Config,
        database: crate::db::Database,
        issuer: IssuerRuntime,
    ) -> Result<Self, StateError> {
        config.validate_cookie_security()?;

        // 静态根先解析：这是纯配置校验，放在生成 RSA 私钥和连 Redis 之前，配置错误
        // 就不会等到副作用做完才暴露。canonicalize 与 stat 是阻塞 I/O，和密钥加载
        // 一样搬到阻塞线程池。
        let web_dist_setting = config.web_dist_dir.clone();
        let key_directory_setting = config.key_directory.clone();
        let web_dist = tokio::task::spawn_blocking(move || {
            WebDistRoot::from_settings(&web_dist_setting, &key_directory_setting)
        })
        .await??;
        tracing::info!(
            event = "web_dist_resolved",
            path = %web_dist.path().display(),
            "静态资源根已校验"
        );

        let redis = RedisClient::open(config.redis_url.as_str())?;
        // 时钟在这里构造一次，往下克隆给每个需要判定过期的 store 与 service。
        let clock = SharedClock::system();

        // 密钥目录的读写和 RSA 生成是同步阻塞调用，直接在 async 上下文执行会占住
        // 当前 worker（`current_thread` 调度器下会让整个运行时停摆）。搬到阻塞线程池，
        // 并按值 move 配置副本，闭包才满足 `'static + Send`。
        let key_directory = config.key_directory.clone();
        let key_retention = Duration::from_secs(config.key_rotation_grace_seconds);
        let key_skew_allowance = Duration::from_secs(config.key_rotation_skew_allowance_seconds);
        let key_activation_delay = Duration::from_secs(config.key_activation_delay_seconds);
        let StartupKeyMaterial {
            keys,
            secrets: secret_manager,
        } = tokio::task::spawn_blocking(move || {
            StartupKeyMaterial::load(
                &key_directory,
                key_retention,
                key_skew_allowance,
                key_activation_delay,
            )
        })
        .await??;

        let settings = SettingsService::with_security_limits(
            database.clone(),
            secret_manager.clone(),
            &config.webauthn_rp_id,
            &config.webauthn_origin,
            SecurityLimitsSetting::from(&config.security_limits),
        )
        .with_issuer_runtime(issuer.clone());

        // 安全阈值从 SettingsService 读取。稳态下命中它的进程内缓存，认证热路径不再
        // 逐次查询 `app_settings`（#300）；管理接口写入后主动刷新该缓存，因此同一进程
        // 内的执行路径立即看到新阈值，多实例部署由缓存 TTL 收敛。
        let auth_limiter: Arc<dyn AuthFailureLimiter> =
            Arc::new(RedisAuthFailureLimiter::with_settings(
                redis.clone(),
                config.auth_limiter_failure_policy,
                settings.clone(),
            ));
        let sessions = SessionStore::with_metadata_and_key_ring(
            redis.clone(),
            database.clone(),
            config.auth_encryption_keys.clone(),
        )
        .with_session_policy(
            Duration::from_secs(config.session_idle_timeout_seconds),
            config.session_max_concurrent_sessions,
        )
        .with_absolute_ttl(Duration::from_secs(config.session_ttl_seconds))
        .with_clock(clock.clone());
        let users = UserService::with_source_ip_policy(
            database.clone(),
            auth_limiter.clone(),
            config.missing_source_ip_policy,
        );
        let factors = AuthFactorService::new_with_source_ip_policy(
            database.clone(),
            redis.clone(),
            auth_limiter,
            config.auth_encryption_keys.clone(),
            settings.clone(),
            config.missing_source_ip_policy,
        )
        .with_clock(clock.clone());
        let authorization_codes =
            AuthorizationCodeStore::new(redis.clone()).with_clock(clock.clone());
        let refresh_tokens = RefreshTokenStore::new(redis.clone()).with_clock(clock.clone());
        // Secret 版本负责兑换时的硬失效；RefreshTokenStore 负责在轮换后立即
        // 清理已经失效的 Redis 记录，避免它们一直占据索引与 TTL（#62/#310）。
        let clients =
            ClientService::with_limits(database.clone(), config.client_registration_limits.clone())
                .with_refresh_tokens(refresh_tokens.clone());
        let authorization_requests =
            AuthorizationRequestStore::new_with_settings(redis.clone(), settings.clone());
        let consents = ConsentService::new(database.clone());
        let revocations = TokenRevocationStore::new_with_pool(redis.clone(), database.clone());
        let oauth_quotas = OAuthQuotaStore::new(redis.clone());
        let qps = QpsRateLimiter::new(redis.clone());
        let plans = PlanService::new(database.clone()).with_clock(clock.clone());
        let admin = AdminAuthenticator::new(config.admin_token.clone());
        let audit = AuditService::new(database.clone()).with_clock(clock.clone());
        // 复用已加载的 secret_manager，避免第二次 load_or_generate 创建独立副本。
        // 出网边界策略来自配置（Issue #343）：回环/明文例外默认关闭。
        let external_oauth = ExternalOAuthService::new(
            database.clone(),
            secret_manager,
            EndpointPolicy::new(config.oauth_provider_loopback_enabled),
        )?;
        let external_login_states =
            ExternalLoginStateStore::new_with_settings(redis.clone(), settings.clone());

        Ok(Self {
            config,
            issuer,
            clock,
            web_dist,
            database,
            redis,
            sessions,
            settings,
            users,
            clients,
            keys,
            authorization_codes,
            refresh_tokens,
            authorization_requests,
            consents,
            revocations,
            oauth_quotas,
            qps,
            plans,
            admin,
            audit,
            factors,
            external_oauth,
            external_login_states,
        })
    }

    /// 周期性回读 Issuer generation。通知只负责降低延迟，轮询才是 PgBouncer 与
    /// 断线场景下的可靠收敛上界；读取失败保留最后一个合法快照。
    pub async fn run_issuer_sync_worker(self) {
        let mut interval = tokio::time::interval(crate::settings::ISSUER_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let expected = self.issuer.state();
            match crate::settings::issuer::load_raw(&self.database).await {
                Ok(record) => match self
                    .issuer
                    .apply_raw_if_unchanged(&expected, record.as_ref())
                {
                    Ok(Some(snapshot)) => tracing::info!(
                        event = "issuer.runtime_applied",
                        generation = snapshot.generation(),
                        issuer = %snapshot.issuer(),
                        "applied persisted issuer to the running instance"
                    ),
                    Ok(None) => {}
                    Err(error_value) => tracing::error!(
                        event = "issuer.runtime_invalid",
                        generation = record.as_ref().map(|record| record.generation),
                        error = %error_value,
                        "persisted issuer is invalid; protocol routes are fail-closed"
                    ),
                },
                Err(error_value) => tracing::warn!(
                    event = "issuer.runtime_reload_failed",
                    error = %error_value,
                    "failed to reload issuer; retaining the last runtime state"
                ),
            }
        }
    }
}
