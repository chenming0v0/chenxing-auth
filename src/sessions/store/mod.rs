//! Session 存储边界。
//!
//! 本文件保留 `SessionStore` 结构体、错误类型、构造函数和共享工具方法。
//! 公开 API 在此调度到两条实现路径：
//!
//! - [`redis_only`]：无 Postgres 元数据时的纯 Redis 路径（开发 / 测试）。
//! - [`postgres`]：带 Postgres 权威记录的生产路径。
//!
//! `pub(crate)` 的 `lock_user_session_scope` 和 `revoke_all_for_user_in_transaction`
//! 在此 re-export，`users::repository` 的既有调用路径不变。

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use time::OffsetDateTime;

use super::{
    SessionOutboxPolicy, crypto,
    domain::{Session, SessionLookup, SessionPayload, SessionPolicy, session_token_hash_bytes},
};
use crate::{
    clock::SharedClock, config::AuthEncryptionKeyRing, redis_client::RedisClient,
    redis_keyspace::RedisKeyspace, users::domain::UserId,
};

mod postgres;
mod redis_only;

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

// 跨边界类型/函数本体在 postgres 子模块，可见性保持 `pub(crate)`：
// `users::repository` 通过 `crate::sessions::store::...` 调用，路径不变。
// 这里必须用 `pub(crate) use` 而非 `pub use`——`pub use` 重导出 `pub(crate)` 条目
// 会触发 E0365。
pub(crate) use postgres::{
    SessionIssuanceGuard, lock_user_session_scope, revoke_all_for_user_in_transaction,
};

#[derive(Clone)]
pub struct SessionStore {
    pub(super) client: RedisClient,
    pub(super) key_prefix: String,
    pub(super) metadata: Option<crate::sqlx::PgPool>,
    pub(super) encryption_keys: Option<AuthEncryptionKeyRing>,
    pub(super) policy: SessionPolicy,
    pub(super) outbox_policy: SessionOutboxPolicy,
    /// 会话有效期、idle 判定和 Redis TTL 的时间来源。
    ///
    /// Postgres 路径的权威判定仍用 SQL 的 `NOW()`（见 `postgres.rs`）：那些
    /// 判定必须与行锁处在同一个事务时间里，不能改读进程时钟。
    pub(super) clock: SharedClock,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("session payload encryption failed")]
    PayloadEncryption,
    #[error("session payload decryption failed")]
    PayloadDecryption,
    #[error("session payload encoding failed")]
    PayloadEncoding,
    #[error("session metadata is unavailable")]
    MetadataUnavailable,
    #[error("session outbox record is invalid")]
    InvalidOutbox,
    #[error("session user id is invalid")]
    InvalidUserId,
    #[error("session user is not active")]
    UserDisabled,
    #[error("session user was not found")]
    UserNotFound,
    #[error("session was rejected by a revocation watermark")]
    SessionRevoked,
    /// 认证时读到的 `session_epoch` 与写入时刻的当前值不一致（Issue #274）。
    ///
    /// 唯一的推进者是"改密并撤销全部会话"，因此这个错误的含义是明确的：
    /// 本次认证依据的口令在签发完成前已被作废，会话不得建立。
    #[error("authenticated session epoch is stale")]
    AuthenticationEpochChanged,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryFactorSessionPersistence {
    Stored,
    TotpBecameRequired,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// 新会话与用户 `session_epoch` 的绑定方式（Issue #274）。
///
/// 三个变体对应三类登录来源：
///
/// - [`SessionEpochBinding::Current`]：外部 IdP 回调、管理侧或测试直接建会话。
/// - [`SessionEpochBinding::Authenticated`]：密码/Passkey 之后的所有本地验证已经完成。
/// - [`SessionEpochBinding::PrimaryFactorAuthenticated`]：密码或 Passkey 第一因子刚完成；
///   写入事务必须同时确认 epoch 未变化且账号没有启用 TOTP，否则返回待验证状态而不落会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEpochBinding {
    Current,
    Authenticated(i64),
    PrimaryFactorAuthenticated { authenticated_epoch: i64 },
}

impl SessionStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: None,
            policy: SessionPolicy::default(),
            outbox_policy: SessionOutboxPolicy::default(),
            clock: SharedClock::system(),
        }
    }

    pub fn with_redis_key(client: impl Into<RedisClient>, encryption_key: [u8; 32]) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: Some(AuthEncryptionKeyRing::single(
                crate::config::AuthEncryptionKey::new(encryption_key),
            )),
            policy: SessionPolicy::default(),
            outbox_policy: SessionOutboxPolicy::default(),
            clock: SharedClock::system(),
        }
    }

    pub fn with_metadata_and_key(
        client: impl Into<RedisClient>,
        metadata: crate::sqlx::PgPool,
        encryption_key: [u8; 32],
    ) -> Self {
        Self::with_metadata_and_key_ring(
            client,
            metadata,
            AuthEncryptionKeyRing::single(crate::config::AuthEncryptionKey::new(encryption_key)),
        )
    }

    pub fn with_metadata_and_key_ring(
        client: impl Into<RedisClient>,
        metadata: crate::sqlx::PgPool,
        encryption_keys: AuthEncryptionKeyRing,
    ) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: Some(metadata),
            encryption_keys: Some(encryption_keys),
            policy: SessionPolicy::default(),
            outbox_policy: SessionOutboxPolicy::default(),
            clock: SharedClock::system(),
        }
    }

    pub fn with_session_policy(
        mut self,
        idle_timeout: Duration,
        max_concurrent_sessions: u64,
    ) -> Self {
        if !idle_timeout.is_zero()
            && time::Duration::try_from(idle_timeout).is_ok()
            && max_concurrent_sessions > 0
        {
            self.policy = SessionPolicy {
                absolute_ttl: self.policy.absolute_ttl,
                idle_timeout,
                max_concurrent_sessions,
            };
        }
        self
    }

    pub fn with_keyspace(mut self, keyspace: RedisKeyspace) -> Self {
        self.key_prefix = keyspace.prefix("chenxing:session:");
        self
    }

    pub fn with_absolute_ttl(mut self, absolute_ttl: Duration) -> Self {
        if !absolute_ttl.is_zero() && time::Duration::try_from(absolute_ttl).is_ok() {
            self.policy.absolute_ttl = absolute_ttl;
        }
        self
    }

    /// 覆盖 outbox 终态策略（保留窗口、清理批量、最大尝试次数）。
    ///
    /// 取值经 [`SessionOutboxPolicy::sanitized`] 收敛，因此不存在"配了 0 批量导致
    /// 清理永远不删"或"配了 0 次尝试导致每个事件立刻进 dead-letter"的组合。
    pub fn with_outbox_policy(mut self, outbox_policy: SessionOutboxPolicy) -> Self {
        self.outbox_policy = outbox_policy.sanitized();
        self
    }

    /// 注入共享时钟（`AppState` 构造时调用）。
    ///
    /// 固定时钟可以把 idle 续期阈值和绝对过期推到边界两侧，因此
    /// 「idle 刚好超时」这类用例不需要真实等待 30 分钟。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// 写入一条采用当前 epoch 的会话。
    ///
    /// 只用于无需绑定本地凭据 epoch 的路径（外部 IdP 回调、管理侧、测试夹具）。
    /// 本地密码、Passkey 与 TOTP 登录必须走带认证 epoch 的写入路径，
    /// 否则并发改密的撤销语义会被绕过（Issue #274）。
    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
        self.save_bound(session, ttl, SessionEpochBinding::Current)
            .await
            .map(|_| ())
    }

    /// 写入一条绑定认证 epoch 的会话。
    ///
    /// `authenticated_epoch` 必须是口令校验时与 `password_hash` 同一次读取取出的
    /// 值。当前 epoch 已经前进时返回
    /// [`SessionStoreError::AuthenticationEpochChanged`]，且事务回滚，不留下任何
    /// 会话行或 outbox 事件——验证失败不产生有效凭据。
    pub async fn save_authenticated(
        &self,
        session: &mut Session,
        ttl: Duration,
        authenticated_epoch: i64,
    ) -> Result<(), SessionStoreError> {
        self.save_bound(
            session,
            ttl,
            SessionEpochBinding::Authenticated(authenticated_epoch),
        )
        .await
        .map(|_| ())
    }

    /// 写入密码或 Passkey 第一因子完成后的候选会话。
    ///
    /// 事务内若发现账号已启用 TOTP，则回滚候选会话并返回
    /// [`PrimaryFactorSessionPersistence::TotpBecameRequired`]。
    pub async fn save_primary_factor_authenticated(
        &self,
        session: &mut Session,
        ttl: Duration,
        authenticated_epoch: i64,
    ) -> Result<PrimaryFactorSessionPersistence, SessionStoreError> {
        self.save_bound(
            session,
            ttl,
            SessionEpochBinding::PrimaryFactorAuthenticated {
                authenticated_epoch,
            },
        )
        .await
    }

    async fn save_bound(
        &self,
        session: &mut Session,
        ttl: Duration,
        binding: SessionEpochBinding,
    ) -> Result<PrimaryFactorSessionPersistence, SessionStoreError> {
        if self.metadata.is_some() {
            postgres::save_with_metadata(self, session, ttl, binding).await
        } else {
            // 纯 Redis 路径没有 users 表可读，无法校验 epoch。缺少校验能力时
            // 拒绝签发，而不是降级成"当作校验通过"：后者会让一条本应被拒绝的
            // 凭据在配置退化时静默生效。生产 AppState 始终带 Postgres 元数据。
            if !matches!(binding, SessionEpochBinding::Current) {
                return Err(SessionStoreError::MetadataUnavailable);
            }
            redis_only::save_redis_only(self, session, ttl).await?;
            Ok(PrimaryFactorSessionPersistence::Stored)
        }
    }

    pub async fn find(&self, token: &str) -> Result<Option<Session>, SessionStoreError> {
        if self.metadata.is_some() {
            postgres::find_with_metadata(self, token).await
        } else {
            redis_only::find_redis_only(self, token).await
        }
    }

    /// Look up active session metadata without requiring or reconstructing the plaintext token.
    pub async fn find_by_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<SessionLookup>, SessionStoreError> {
        if self.metadata.is_some() {
            postgres::find_with_metadata_by_token_hash(self, token_hash).await
        } else {
            redis_only::find_redis_only_by_token_hash(self, token_hash).await
        }
    }

    /// Acquire the final PostgreSQL ordering boundary for token issuance.
    pub(crate) async fn acquire_issuance_guard(
        &self,
        session_id: i64,
        user_id: UserId,
        token_hash: &[u8],
        expected_epoch: i64,
    ) -> Result<Option<SessionIssuanceGuard>, SessionStoreError> {
        if self.metadata.is_none() {
            return Err(SessionStoreError::MetadataUnavailable);
        }
        postgres::acquire_issuance_guard(self, session_id, user_id, token_hash, expected_epoch)
            .await
    }

    /// Session-less `session_epoch` fence after Refresh Token rotation.
    pub(crate) async fn acquire_user_generation_guard(
        &self,
        user_id: UserId,
        expected_epoch: i64,
    ) -> Result<Option<SessionIssuanceGuard>, SessionStoreError> {
        if self.metadata.is_none() {
            return Err(SessionStoreError::MetadataUnavailable);
        }
        postgres::acquire_user_generation_guard(self, user_id, expected_epoch).await
    }

    pub async fn revoke(&self, token: &str) -> Result<(), SessionStoreError> {
        let hash = session_token_hash_bytes(token).to_vec();
        if self.metadata.is_none() {
            redis_only::revoke_redis_only(self, &hash).await
        } else {
            postgres::revoke_by_token_hash(self, &hash).await
        }
    }

    pub async fn list_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<SessionSummary>, SessionStoreError> {
        postgres::list_for_user(self, user_id).await
    }

    pub async fn revoke_for_user(
        &self,
        user_id: UserId,
        session_id: i64,
    ) -> Result<bool, SessionStoreError> {
        postgres::revoke_for_user(self, user_id, session_id).await
    }

    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<(), SessionStoreError> {
        if self.metadata.is_some() {
            postgres::revoke_all_for_user(self, user_id).await
        } else {
            redis_only::revoke_all_redis_only(self, user_id).await
        }
    }

    pub(super) fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        crypto::encrypt(keys, payload)
    }

    /// 解密并解析持久化载荷。
    ///
    /// 解密或解析失败返回 `Ok(None)`，由调用方按"会话不存在"处理，避免把密钥配置
    /// 问题和损坏数据变成可探测的错误差异。缺少密钥环属于配置错误，仍然返回 `Err`。
    ///
    /// 升级前写入的载荷含有 `token` 字段；`SessionPayload` 未标注
    /// `deny_unknown_fields`，serde 会忽略这个多余字段，因此历史数据继续可读。
    pub(super) fn decode_payload(
        &self,
        payload: &[u8],
    ) -> Result<Option<SessionPayload>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        Ok(crypto::decrypt(keys, payload)
            .ok()
            .and_then(|payload| serde_json::from_slice(&payload).ok()))
    }

    pub(super) fn key(&self, token: &str) -> String {
        self.key_hash(&session_token_hash_bytes(token))
    }

    pub(super) fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }

    pub(super) fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-epoch:{user_id}", self.key_prefix)
    }

    pub(super) fn redis_only_revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }

    pub(super) fn redis_only_token_revocation_key(&self, hash: &[u8]) -> String {
        format!(
            "{}revoked-token:{}",
            self.key_prefix,
            URL_SAFE_NO_PAD.encode(hash)
        )
    }

    pub(super) fn redis_only_token_renewal_key(&self, hash: &[u8]) -> String {
        format!(
            "{}renewed-token:{}",
            self.key_prefix,
            URL_SAFE_NO_PAD.encode(hash)
        )
    }

    pub(super) fn idle_timeout_interval(&self) -> time::Duration {
        time::Duration::seconds(
            i64::try_from(self.policy.idle_timeout.as_secs())
                .unwrap_or(i64::MAX)
                .max(1),
        )
    }

    pub(super) fn renewal_interval(&self) -> time::Duration {
        time::Duration::seconds(
            i64::try_from(self.policy.idle_timeout.as_secs() / 2)
                .unwrap_or(i64::MAX)
                .max(1),
        )
    }

    /// 撤销标记（单条 tombstone 与用户级水位）的存活时长。
    ///
    /// 取绝对 Session TTL 是安全的下限：任何会话键的存活窗口都不超过
    /// [`Self::redis_ttl_seconds`]，而后者同样被这个值封顶（见该函数注释），
    /// 因此"撤销标记先于被它拦截的会话键消失"不可能发生。
    ///
    /// 启动配置把 `SESSION_TTL_SECONDS` 封顶在 90 天（#365），所以这个值
    /// 必然落在 Redis `EX` 的 i64 上限内，不会触发 `ERR invalid expire time`。
    pub(super) fn revocation_ttl_seconds(&self) -> u64 {
        self.policy.absolute_ttl.as_secs().max(1)
    }

    /// 会话键在 Redis 的存活秒数。
    ///
    /// 除了绝对过期与 idle 截止，这里还被 [`Self::revocation_ttl_seconds`] 封顶。
    /// 这一层封顶是撤销水位 TTL 的安全前提：水位在撤销时刻 `T` 写入并带上
    /// `EX = revocation_ttl`，而任何在 `T` 之前写入的会话键最晚也在
    /// `写入时刻 + revocation_ttl <= T + revocation_ttl` 过期。水位不会先于它
    /// 应当拦截的旧会话消失，旧会话也就不可能在水位过期后复活。
    /// 调用方传入的 `absolute_ttl` 只能收紧、不能放宽这个上限。
    pub(super) fn redis_ttl_seconds(
        &self,
        session: &Session,
        absolute_ttl: Duration,
        now: OffsetDateTime,
    ) -> u64 {
        let absolute = (session.expires_at - now).whole_seconds().max(1) as u64;
        let idle = session
            .idle_deadline()
            .map(|deadline| (deadline - now).whole_seconds().max(1) as u64)
            .unwrap_or(absolute);
        absolute
            .min(idle)
            .min(absolute_ttl.as_secs().max(1))
            .min(self.revocation_ttl_seconds())
    }
}

pub(super) fn timestamp_watermark(value: OffsetDateTime) -> i64 {
    value
        .unix_timestamp_nanos()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64
}
