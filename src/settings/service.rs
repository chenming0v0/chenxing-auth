use std::sync::Arc;

use super::{
    IssuerRuntime, SecurityLimitsSetting,
    domain::{
        PasskeySetting, SettingsValidationError, SmtpSetting, SmtpSettingUpdate, StoredSmtpSetting,
    },
    repository,
    security_limits_cache::{CachedSecurityLimits, SecurityLimitsCache, SecurityLimitsSource},
    smtp_sender::parse_smtp_sender,
};
use crate::{
    config::AuthEncryptionKey,
    oauth::providers::secrets::{SecretError, SecretManager},
    users::email::EmailAddress,
};
use thiserror::Error;

#[path = "service_persisted.rs"]
mod persisted_reads;

#[derive(Clone)]
pub struct SettingsService {
    pool: crate::sqlx::PgPool,
    secrets: SecretManager,
    default_passkey: PasskeySetting,
    /// 启动期默认阈值（来自环境变量配置），同时是缓存的初始「最后已知安全值」。
    default_security_limits: SecurityLimitsSetting,
    /// 认证热路径共享的阈值缓存（#300）。`Arc` 让本服务的全部克隆共享同一份状态，
    /// 因此管理接口写入后的主动刷新对同进程内所有读取路径立即生效。
    security_limits_cache: Arc<SecurityLimitsCache>,
    issuer_runtime: Option<IssuerRuntime>,
}

#[derive(Debug, Error)]
pub enum SettingsServiceError {
    #[error("registration sender email is invalid")]
    InvalidEmail,
    #[error("setting validation failed: {0}")]
    Validation(#[from] SettingsValidationError),
    #[error("stored setting {key} is unreadable")]
    Corrupt { key: &'static str },
    #[error("secret operation failed: {0}")]
    Secret(#[from] SecretError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl SettingsService {
    pub fn new(
        pool: crate::sqlx::PgPool,
        secrets: SecretManager,
        default_rp_id: &str,
        default_origin: &str,
    ) -> Self {
        Self::with_security_limits(
            pool,
            secrets,
            default_rp_id,
            default_origin,
            SecurityLimitsSetting::default(),
        )
    }

    pub fn with_security_limits(
        pool: crate::sqlx::PgPool,
        secrets: SecretManager,
        default_rp_id: &str,
        default_origin: &str,
        default_security_limits: SecurityLimitsSetting,
    ) -> Self {
        Self {
            pool,
            secrets,
            default_passkey: PasskeySetting::default()
                .with_runtime_defaults(default_rp_id, default_origin),
            security_limits_cache: Arc::new(SecurityLimitsCache::new(
                default_security_limits.clone(),
            )),
            default_security_limits,
            issuer_runtime: None,
        }
    }

    pub fn with_issuer_runtime(mut self, issuer_runtime: IssuerRuntime) -> Self {
        self.issuer_runtime = Some(issuer_runtime);
        self
    }

    /// 用自定义 TTL / 退避的缓存替换默认缓存。仅用于测试缓存与降级路径。
    #[cfg(test)]
    pub(crate) fn with_security_limits_cache(mut self, cache: SecurityLimitsCache) -> Self {
        self.security_limits_cache = Arc::new(cache);
        self
    }

    /// 构造一个 settings 读取必然失败的服务：连接池指向不可达地址，
    /// `connect_lazy` 不在构造时连接，第一次查询才失败。
    ///
    /// 用于验证阈值读取故障时的降级取值与 `AuthLimiterFailurePolicy` 分发（#300），
    /// 不需要真实 PostgreSQL。`acquire_timeout` 必须显式压到 100ms：默认 30 秒会让
    /// 每个降级用例干等半分钟。
    #[cfg(test)]
    pub(crate) fn unreachable_for_tests(default_security_limits: SecurityLimitsSetting) -> Self {
        let pool = crate::sqlx::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        Self::with_security_limits(
            pool,
            SecretManager::from_key([0_u8; 32]),
            "localhost",
            "http://localhost",
            default_security_limits,
        )
    }

    pub fn from_encryption_key(
        pool: crate::sqlx::PgPool,
        encryption_key: &AuthEncryptionKey,
        default_rp_id: &str,
        default_origin: &str,
    ) -> Self {
        Self::new(
            pool,
            SecretManager::from_key(*encryption_key.as_bytes()),
            default_rp_id,
            default_origin,
        )
    }

    pub async fn registration_email_from(&self) -> Result<Option<String>, SettingsServiceError> {
        let smtp = self.smtp().await?;
        if !smtp.from_address.is_empty()
            && let Some(email) = extract_email(&smtp.from_address)
        {
            return Ok(Some(email));
        }
        Ok(repository::get_registration_email_from(&self.pool).await?)
    }

    pub async fn set_registration_email_from(
        &self,
        value: Option<String>,
    ) -> Result<Option<String>, SettingsServiceError> {
        let value = normalize_email(value)?;
        // 独立值与 SMTP from 镜像必须一起落库：第二次写失败时若第一个键已持久化
        // 会形成「独立值已更新、SMTP 残留旧地址」的半同步状态（#322），
        // 用单事务保证要么都生效、要么都回滚。
        let mut transaction = self.pool.begin().await?;
        repository::set_registration_email_from(&mut *transaction, value.as_deref()).await?;
        match value.as_deref() {
            Some(email) => {
                // 首次配置发件人时回填 SMTP from；SMTP from 已存在（由 SMTP 表单管理）则不动。
                let mut smtp = repository::get_smtp(&mut *transaction)
                    .await?
                    .unwrap_or_else(|| StoredSmtpSetting {
                        host: String::new(),
                        port: 587,
                        username: String::new(),
                        from_address: String::new(),
                        ssl_enabled: true,
                        force_auth_login: false,
                        password_ciphertext: None,
                    });
                if smtp.from_address.trim().is_empty() {
                    smtp.from_address = email.to_owned();
                    repository::set_smtp(&mut *transaction, &smtp).await?;
                }
            }
            None => {
                // 清除的对称处理（#414）：SMTP from 是注册发件人的镜像（设置路径会回填，
                // `set_smtp` 也会把非空 from 同步进独立值），而读取路径 SMTP from 优先。
                // 只清独立值会让残留旧地址继续生效；非空 SMTP from 即当前生效发件人，
                // 清除请求必须一并清掉它，包括修复已处于「独立值已空、SMTP 残留」状态的行。
                if let Some(mut smtp) = repository::get_smtp(&mut *transaction).await?
                    && !smtp.from_address.trim().is_empty()
                {
                    smtp.from_address.clear();
                    repository::set_smtp(&mut *transaction, &smtp).await?;
                }
            }
        }
        transaction.commit().await?;
        Ok(value)
    }

    /// 读取已校验的安全阈值，命中未过期缓存时不查询数据库。
    ///
    /// 这是 OAuth 授权 / 令牌等安全热路径：损坏或越界的已持久化值返回 `Err`
    /// （fail-closed），不再 `sanitized()` 成一次成功加载。管理读取走
    /// [`Self::inspect_security_limits`]。限流器要用降级而不是报错时走
    /// [`Self::cached_security_limits`]。
    pub async fn security_limits(&self) -> Result<SecurityLimitsSetting, SettingsServiceError> {
        if let Some(cached) = self.security_limits_cache.fresh() {
            return Ok(cached);
        }
        self.load_and_cache_security_limits().await
    }

    /// 认证限流热路径使用的读取：永远返回一份可用阈值，并说明它的来源。
    ///
    /// 失败时不返回 `Err`，而是给出最后已知安全值或启动期默认值并标记为降级，由
    /// 调用方按 `AuthLimiterFailurePolicy` 决定放行还是拒绝（#300）。读取失败后进入
    /// 退避窗口，故障期间不会每个请求都再打一次数据库。
    pub async fn cached_security_limits(&self) -> CachedSecurityLimits {
        if let Some(value) = self.security_limits_cache.fresh() {
            return CachedSecurityLimits {
                value,
                source: SecurityLimitsSource::Cache,
            };
        }
        if let Some(backed_off) = self.security_limits_cache.backoff_fallback() {
            return backed_off;
        }
        match self.load_and_cache_security_limits().await {
            Ok(value) => CachedSecurityLimits {
                value,
                source: SecurityLimitsSource::Loaded,
            },
            Err(error_value) => {
                tracing::error!(
                    event = "settings.security_limits_load_failed",
                    error = %error_value,
                    "failed to load security limits; falling back to the last known safe value"
                );
                self.security_limits_cache.record_failure()
            }
        }
    }

    /// 加载并把结果写回缓存；加载期间若有管理员写入（代际推进），本次结果被丢弃。
    ///
    /// #413：读库时刻与写缓存时刻分离，中间可插入管理员的写入。先捕获代际、完成后
    /// CAS 回填，让旧快照无法覆盖新阈值。返回的仍是本次读到的值——它与读库时刻的
    /// 数据库快照一致，仅不再回填缓存。
    async fn load_and_cache_security_limits(
        &self,
    ) -> Result<SecurityLimitsSetting, SettingsServiceError> {
        let generation = self.security_limits_cache.generation();
        let value = self.load_security_limits().await?;
        if !self
            .security_limits_cache
            .store_if_generation_unchanged(generation, value.clone())
        {
            tracing::debug!(
                event = "settings.security_limits_stale_reload_discarded",
                "discarding stale security limits reload: an administrator write landed while the load was in flight"
            );
        }
        Ok(value)
    }

    pub async fn set_security_limits(
        &self,
        value: SecurityLimitsSetting,
    ) -> Result<SecurityLimitsSetting, SettingsServiceError> {
        let value = value.validate()?;
        repository::set_security_limits(&self.pool, &value).await?;
        // 写入成功后主动刷新缓存，而不是只失效：新值已经校验过，等价于一次成功加载。
        // 否则本实例在 TTL 内仍按旧阈值限流，管理员在设置页看不到自己的改动生效。
        // 多实例部署里其他实例靠 TTL 收敛，窗口上界是 SECURITY_LIMITS_CACHE_TTL。
        // `store` 会推进代际（#413）：早于本次写入开始、晚于本次写入完成才落地的
        // 并发过期加载会因代际不匹配被丢弃，不会用旧阈值回填覆盖刚写入的新值。
        self.security_limits_cache.store(value.clone());
        Ok(value)
    }

    pub async fn smtp(&self) -> Result<SmtpSetting, SettingsServiceError> {
        Ok(match repository::get_smtp(&self.pool).await? {
            Some(stored) => SmtpSetting {
                host: stored.host,
                port: stored.port,
                username: stored.username,
                from_address: stored.from_address,
                ssl_enabled: stored.ssl_enabled,
                force_auth_login: stored.force_auth_login,
                password_configured: stored
                    .password_ciphertext
                    .as_ref()
                    .is_some_and(|value| !value.is_empty()),
            },
            None => {
                let mut setting = SmtpSetting::default();
                if let Some(from) = repository::get_registration_email_from(&self.pool).await? {
                    setting.from_address = from;
                }
                setting
            }
        })
    }

    pub async fn set_smtp(
        &self,
        update: SmtpSettingUpdate,
    ) -> Result<SmtpSetting, SettingsServiceError> {
        let (mut setting, password) = update.validate()?;
        // SMTP 与注册发件人镜像必须一起落库：第二次写失败时若第一个键已持久化
        // 会形成「SMTP 已更新、镜像残留旧地址」的半同步状态（#322）。
        // 事务内读取 existing，保证「未提供新密码则沿用旧密文」看到的是同一快照。
        let mut transaction = self.pool.begin().await?;
        let existing = repository::get_smtp(&mut *transaction).await?;
        let password_ciphertext = match password {
            Some(password) => Some(SecretManager::encode(&self.secrets.encrypt(&password)?)),
            None => existing
                .as_ref()
                .and_then(|value| value.password_ciphertext.clone()),
        };
        setting.password_configured = password_ciphertext
            .as_ref()
            .is_some_and(|value| !value.is_empty());
        let stored = StoredSmtpSetting {
            host: setting.host.clone(),
            port: setting.port,
            username: setting.username.clone(),
            from_address: setting.from_address.clone(),
            ssl_enabled: setting.ssl_enabled,
            force_auth_login: setting.force_auth_login,
            password_ciphertext,
        };
        repository::set_smtp(&mut *transaction, &stored).await?;
        // 镜像同步必须双向（#321）：非空 from 写入独立键；from 清空时删除该键。
        // `validate` 已保证非空 from 可解析，`None` 分支只可能来自显式清空。只写
        // 不删会让读取路径（`registration_email_from`，SMTP from 为空时回退到独立
        // 键）命中残留旧地址，已停用的发件人在注册邮件里复活；与
        // `set_registration_email_from` 清除时同步清 SMTP from 的方向对称。
        match extract_email(&setting.from_address) {
            Some(email) => {
                repository::set_registration_email_from(&mut *transaction, Some(&email)).await?
            }
            None => repository::set_registration_email_from(&mut *transaction, None).await?,
        }
        transaction.commit().await?;
        Ok(setting)
    }
}

/// 发件人邮箱的规范化。
///
/// 走 [`EmailAddress`] 这一个入口（Issue #302），取展示值：这个地址会进入 SMTP
/// 的 `From` 头，需要的是给人看的形态，而域名已经被规范化成可传输的 ASCII。
/// 它不是账号标识符，因此不需要匹配值。
fn normalize_email(value: Option<String>) -> Result<Option<String>, SettingsServiceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    EmailAddress::parse(&value)
        .map(|email| Some(email.into_display()))
        .map_err(|_| SettingsServiceError::InvalidEmail)
}

/// 从 `Name <a@b>` 或裸邮箱里取出规范化后的展示值。
fn extract_email(value: &str) -> Option<String> {
    parse_smtp_sender(value).map(EmailAddress::into_display)
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
