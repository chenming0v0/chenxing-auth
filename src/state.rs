use std::{sync::Arc, time::Duration};

use redis::Client;

use crate::{
    admin::AdminAuthenticator,
    audit::AuditService,
    auth_factors::service::AuthFactorService,
    auth_limiter::{AuthFailureLimiter, RedisAuthFailureLimiter},
    clients::service::ClientService,
    config::Config,
    consents::ConsentService,
    db::Database,
    keys::{KeyManager, KeyManagerError},
    oauth::providers::{
        secrets::SecretManager, service::ExternalOAuthService, state_store::ExternalLoginStateStore,
    },
    oauth::quota::OAuthQuotaStore,
    oauth::rate_limit::QpsRateLimiter,
    oauth::refresh_store::RefreshTokenStore,
    oauth::request_store::AuthorizationRequestStore,
    oauth::revocation::TokenRevocationStore,
    oauth::store::AuthorizationCodeStore,
    plans::service::PlanService,
    sessions::store::SessionStore,
    settings::SettingsService,
    users::service::UserService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub database: Database,
    pub redis: Client,
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
    #[error("database configuration is invalid: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("redis configuration is invalid: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("key manager initialization failed: {0}")]
    Keys(#[from] KeyManagerError),
    #[error("external OAuth initialization failed: {0}")]
    ExternalOAuth(#[from] crate::oauth::providers::service::ExternalOAuthError),
    #[error("external OAuth secret initialization failed: {0}")]
    ExternalOAuthSecret(#[from] crate::oauth::providers::secrets::SecretError),
    /// 密钥加载放在阻塞线程池执行，线程 panic 或被取消时只能观察到 JoinError。
    /// 保留这个变体而不是 unwrap，启动失败时才不会丢掉真实原因。
    #[error("key material initialization task failed: {0}")]
    KeyMaterialTask(#[from] tokio::task::JoinError),
}

/// 启动阶段一次性加载的密钥材料。
///
/// `KeyManager` 与 `SecretManager` 都直接读写 `KEY_DIRECTORY` 下的文件，缺失时
/// 还会生成 RSA 2048 私钥，属于典型的阻塞 I/O 加 CPU 密集步骤。打包成一个结构体
/// 是为了只做一次 `spawn_blocking` 往返，而不是每个密钥各跨一次线程。
struct StartupKeyMaterial {
    keys: KeyManager,
    secrets: SecretManager,
}

impl StartupKeyMaterial {
    /// 同步加载全部密钥材料，只允许在 `spawn_blocking` 的阻塞线程里调用。
    fn load(key_directory: &str, key_retention: Duration) -> Result<Self, StateError> {
        // 保持与历史实现一致的失败顺序：先 provider secret，再签名密钥。
        let secrets = SecretManager::load_or_generate(key_directory)?;
        let keys = KeyManager::load_or_generate_with_retention(key_directory, key_retention)?;
        Ok(Self { keys, secrets })
    }
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, StateError> {
        let database = crate::db::connect(&config)?;
        let redis = redis::Client::open(config.redis_url.as_str())?;

        // 密钥目录的读写和 RSA 生成是同步阻塞调用，直接在 async 上下文执行会占住
        // 当前 worker（`current_thread` 调度器下会让整个运行时停摆）。搬到阻塞线程池，
        // 并按值 move 配置副本，闭包才满足 `'static + Send`。
        let key_directory = config.key_directory.clone();
        let key_retention = Duration::from_secs(config.key_rotation_grace_seconds);
        let StartupKeyMaterial {
            keys,
            secrets: secret_manager,
        } = tokio::task::spawn_blocking(move || {
            StartupKeyMaterial::load(&key_directory, key_retention)
        })
        .await??;

        let auth_limiter: Arc<dyn AuthFailureLimiter> =
            Arc::new(RedisAuthFailureLimiter::with_failure_policy(
                redis.clone(),
                config.auth_limiter_failure_policy,
            ));
        let sessions = SessionStore::with_metadata_and_key_ring(
            redis.clone(),
            database.clone(),
            config.auth_encryption_keys.clone(),
        );
        let settings = SettingsService::new(
            database.clone(),
            secret_manager.clone(),
            &config.webauthn_rp_id,
            &config.webauthn_origin,
        );
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
        );
        let clients =
            ClientService::with_limits(database.clone(), config.client_registration_limits.clone());
        let authorization_codes = AuthorizationCodeStore::new(redis.clone());
        let refresh_tokens = RefreshTokenStore::new(redis.clone());
        let authorization_requests = AuthorizationRequestStore::new(redis.clone());
        let consents = ConsentService::new(database.clone());
        let revocations = TokenRevocationStore::new_with_pool(redis.clone(), database.clone());
        let oauth_quotas = OAuthQuotaStore::new(redis.clone());
        let qps = QpsRateLimiter::new(redis.clone());
        let plans = PlanService::new(database.clone());
        let admin = AdminAuthenticator::new(config.admin_token.clone());
        let audit = AuditService::new(database.clone());
        // 复用已加载的 secret_manager，避免第二次 load_or_generate 创建独立副本。
        let external_oauth = ExternalOAuthService::new(database.clone(), secret_manager)?;
        let external_login_states = ExternalLoginStateStore::new(redis.clone());

        Ok(Self {
            config,
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

    pub async fn for_test() -> Self {
        let config = Config::from_values(
            "127.0.0.1".to_owned(),
            3000,
            "postgres://localhost/chenxing_auth".to_owned(),
            "redis://localhost".to_owned(),
            3600,
        )
        .expect("test configuration");

        Self::new(config).await.expect("test state")
    }
}
