use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::clock::{Clock, SystemClock};

pub const DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS: u64 = 1_800;
pub const DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS: u64 = 5;
pub const DEFAULT_SESSION_ABSOLUTE_TTL_SECONDS: u64 = 604_800;
/// `OffsetDateTime` 可表示的最大 epoch 秒数（9999-12-31T23:59:59Z）：time crate
/// 默认未启用 `large-dates`，年份范围只有 ±9999。`TimeDuration::try_from` 的上界
/// （i64 秒，约 2920 亿年）远宽于此，TTL 落入两者之间时 `now + ttl` 的 Add 实现
/// 会 panic。配置校验（启动期 fail-fast）与本模块的 `checked_add`（运行期
/// fail-closed）共用该边界，保证两种路径的语义一致。
pub const MAX_SESSION_TTL_SECONDS: u64 = 253_402_300_799;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    pub absolute_ttl: Duration,
    pub idle_timeout: Duration,
    pub max_concurrent_sessions: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            absolute_ttl: Duration::from_secs(DEFAULT_SESSION_ABSOLUTE_TTL_SECONDS),
            idle_timeout: Duration::from_secs(DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS),
            max_concurrent_sessions: DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
        }
    }
}

/// 运行时会话结构，`token` 字段保存明文会话令牌。
///
/// 刻意不派生 `Serialize` / `Deserialize`：一旦可序列化，明文令牌就有可能被写进
/// 持久化载荷、日志或 API 响应。持久化统一走 [`SessionPayload`]，由类型系统保证
/// 明文令牌不会进入存储；新增字段时也不会因为忘记标注属性而重新泄露凭据。
#[derive(Clone)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
    /// `users.session_epoch` bound to this persisted credential.
    ///
    /// New in-memory sessions have no generation until the metadata transaction commits. Loaded
    /// PostgreSQL sessions always carry the generation from their `user_sessions` row, so a
    /// management write can revalidate the exact Cookie credential instead of re-reading and
    /// accidentally adopting a newer user generation (Issue #493).
    credential_generation: Option<i64>,
    idle_timeout: Option<Duration>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("csrf_token", &"<redacted>")
            .field("revoked_at", &self.revoked_at)
            .field("credential_generation", &self.credential_generation)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

/// 会话持久化载荷结构。
///
/// 与 `Session` 结构体的区别：`token` 字段被排除在外。
///
/// **安全原因**：
/// - `token` 是明文会话令牌，属于敏感凭据。
/// - 数据库和 Redis 已经通过 `token_hash` (SHA-256) 建立索引，查询时不需要明文。
/// - `find()` 在返回会话前无条件用调用方传入的令牌覆盖 `token` 字段，
///   持久化的 token 值从未被读取使用。
/// - 将明文令牌存入可解密载荷会扩大密钥泄露的影响面：攻击者获得
///   `AUTH_ENCRYPTION_KEY` 和数据库备份后，可批量还原所有活跃会话令牌并冒充用户；
///   如果载荷不含 token，同样的泄露只能拿到 `csrf_token` 等辅助字段，无法得到可用令牌。
///
/// **向后兼容**：
/// - 升级前写入的旧载荷包含 `token` 字段。
/// - 反序列化时，serde 默认忽略未知字段（除非显式标注 `deny_unknown_fields`），
///   因此旧载荷中多出的 `token` 会被静默丢弃，不会导致解析失败。
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionPayload {
    /// 格式兼容字段。PostgreSQL 新写入的载荷使用预分配的最终行 ID；读取时仍以
    /// `user_sessions.id` 为权威并覆盖此值，以兼容旧的 `0` 占位载荷。Redis-only
    /// 路径继续使用既有的 `0` 占位。
    pub id: i64,
    // token 字段被移除：它是明文凭据且在查询时被调用方传入值覆盖，持久化它没有必要且扩大了密钥泄露的影响面
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    // Option 保留升级前载荷的可读性；缺失时按 created_at 作为初始 last_seen。
    #[serde(default)]
    pub last_seen_at: Option<OffsetDateTime>,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
    /// Issuance-time idle window in seconds. Missing on pre-#644 payloads;
    /// those sessions fall back to the boot-time store policy on Redis-only
    /// lookup. PostgreSQL lookup uses the `user_sessions.idle_timeout_seconds`
    /// column instead of this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u64>,
}

impl fmt::Debug for SessionPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPayload")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("csrf_token", &"<redacted>")
            .field("revoked_at", &self.revoked_at)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .finish()
    }
}

/// Hash-only session metadata returned when the caller has a token digest but
/// deliberately does not have the plaintext token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLookup {
    pub id: i64,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub(crate) idle_timeout: Option<Duration>,
}

impl SessionLookup {
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none()
            && now < self.expires_at
            && idle_active_at(self.last_seen_at, self.idle_timeout, now)
    }

    /// 用进程默认时钟判定活跃。
    ///
    /// 生产路径一律传入 `AppState` 的共享时钟（[`Self::is_active_at`]）；保留这个
    /// 包装是为了让不持有状态的调用点和测试断言不必自己取时间。
    pub fn is_active(&self) -> bool {
        self.is_active_at(SystemClock.now())
    }
}

impl From<&Session> for SessionPayload {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id.clone(),
            created_at: session.created_at,
            expires_at: session.expires_at,
            last_seen_at: Some(session.last_seen_at),
            csrf_token: session.csrf_token.clone(),
            revoked_at: session.revoked_at,
            idle_timeout_seconds: session.idle_timeout.map(|timeout| timeout.as_secs()),
        }
    }
}

impl SessionPayload {
    /// 将持久化载荷转换回运行时会话结构，使用调用方提供的会话令牌。
    ///
    /// `token` 参数通常是请求中携带的会话凭据（Cookie 或 Authorization 头部），
    /// 它已经通过 `token_hash` 定位到了对应的会话记录。
    pub fn into_session(self, token: String) -> Session {
        Session {
            id: self.id,
            token,
            user_id: self.user_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_seen_at: self.last_seen_at.unwrap_or(self.created_at),
            csrf_token: self.csrf_token,
            revoked_at: self.revoked_at,
            credential_generation: None,
            idle_timeout: idle_timeout_from_seconds(self.idle_timeout_seconds),
        }
    }

    pub fn into_lookup(self) -> SessionLookup {
        SessionLookup {
            id: self.id,
            user_id: self.user_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_seen_at: self.last_seen_at.unwrap_or(self.created_at),
            revoked_at: self.revoked_at,
            idle_timeout: idle_timeout_from_seconds(self.idle_timeout_seconds),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionCredential {
    pub token: String,
    pub token_hash: [u8; 32],
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredential")
            .field("token", &"<redacted>")
            .field("token_hash", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session user id is empty")]
    EmptyUserId,
    #[error("session TTL must be greater than zero")]
    ZeroTtl,
    #[error("session TTL is outside the supported time range")]
    TtlOutOfRange,
    #[error("session idle timeout must be greater than zero")]
    ZeroIdleTimeout,
    #[error("session idle timeout is outside the supported time range")]
    IdleTimeoutOutOfRange,
}

impl Session {
    /// 用进程默认时钟创建会话。
    ///
    /// 生产的登录路径调用 [`Self::new_at_with_idle_timeout`] 并传入 `AppState`
    /// 的共享时钟，使 `created_at` / `expires_at` 与后续的过期判定同源。
    pub fn new(user_id: String, ttl: Duration) -> Result<Self, SessionError> {
        Self::new_at(user_id, ttl, SystemClock.now())
    }

    pub fn new_at(
        user_id: String,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> Result<Self, SessionError> {
        Self::new_at_inner(
            user_id,
            ttl,
            Some(SessionPolicy::default().idle_timeout),
            now,
        )
    }

    pub fn new_with_idle_timeout(
        user_id: String,
        ttl: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, SessionError> {
        Self::new_at_with_idle_timeout(user_id, ttl, idle_timeout, SystemClock.now())
    }

    pub fn new_at_with_idle_timeout(
        user_id: String,
        ttl: Duration,
        idle_timeout: Duration,
        now: OffsetDateTime,
    ) -> Result<Self, SessionError> {
        if idle_timeout.is_zero() {
            return Err(SessionError::ZeroIdleTimeout);
        }
        Self::new_at_inner(user_id, ttl, Some(idle_timeout), now)
    }

    fn new_at_inner(
        user_id: String,
        ttl: Duration,
        idle_timeout: Option<Duration>,
        now: OffsetDateTime,
    ) -> Result<Self, SessionError> {
        if user_id.trim().is_empty() {
            return Err(SessionError::EmptyUserId);
        }
        if ttl.is_zero() {
            return Err(SessionError::ZeroTtl);
        }
        if idle_timeout.is_some_and(|timeout| TimeDuration::try_from(timeout).is_err()) {
            return Err(SessionError::IdleTimeoutOutOfRange);
        }
        let ttl = TimeDuration::try_from(ttl).map_err(|_| SessionError::TtlOutOfRange)?;
        // `now + ttl` 的 Add 实现会在结果超出 `OffsetDateTime` 范围（±9999 年）时
        // panic，而 `TimeDuration::try_from` 的上界比这宽得多；同一个溢出点必须用
        // `checked_add` 转成可控错误（fail-closed），与 `idle_deadline` 的处理一致。
        let expires_at = now.checked_add(ttl).ok_or(SessionError::TtlOutOfRange)?;
        let credential = generate_credential();
        let mut csrf_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        Ok(Self {
            id: 0,
            token: credential.token,
            user_id,
            created_at: now,
            expires_at,
            last_seen_at: now,
            csrf_token: URL_SAFE_NO_PAD.encode(csrf_bytes),
            revoked_at: None,
            credential_generation: None,
            idle_timeout,
        })
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none()
            && now < self.expires_at
            && idle_active_at(self.last_seen_at, self.idle_timeout, now)
    }

    pub(crate) fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    pub(crate) fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = Some(idle_timeout);
    }

    /// Pre-#644 payloads omit the issuance window. Those sessions were
    /// evaluated against the boot-time store policy; do not overwrite a
    /// persisted value with a later admin or boot setting.
    pub(crate) fn restore_idle_timeout(&mut self, fallback: Duration) {
        if self.idle_timeout.is_none() {
            self.idle_timeout = Some(fallback);
        }
    }

    /// Credential generation recorded by the authoritative session metadata row.
    pub fn credential_generation(&self) -> Option<i64> {
        self.credential_generation
    }

    pub(crate) fn set_credential_generation(&mut self, generation: i64) {
        self.credential_generation = Some(generation);
    }

    pub(crate) fn idle_deadline(&self) -> Option<OffsetDateTime> {
        self.idle_timeout
            .and_then(|timeout| idle_deadline(self.last_seen_at, timeout))
    }

    /// 用进程默认时钟标记撤销。
    ///
    /// 生产的撤销走 store（Postgres 路径用 SQL `NOW()`，纯 Redis 路径写撤销
    /// 水位），不经过这个方法；它留给直接操作 `Session` 值的调用点。
    pub fn revoke(&mut self) {
        self.revoke_at(SystemClock.now());
    }

    pub fn revoke_at(&mut self, now: OffsetDateTime) {
        self.revoked_at = Some(now);
    }

    /// 用进程默认时钟判定活跃，语义同 [`SessionLookup::is_active`]。
    pub fn is_active(&self) -> bool {
        self.is_active_at(SystemClock.now())
    }

    /// 校验双提交模式下的 CSRF 令牌。
    ///
    /// CSRF 令牌是安全凭据，比较必须是常量时间的：`String` 的 `==` 逐字节短路，
    /// 耗时与公共前缀长度相关，理论上允许攻击者对同一会话反复请求、按字节逐位
    /// 猜出 43 字符的令牌。
    pub fn validates_csrf(&self, token: &str) -> bool {
        // 空令牌一律拒绝：缺失的 CSRF 头部不能被当成校验通过。
        // 这里短路是安全的，"令牌是否为空"不是秘密。
        if token.is_empty() {
            return false;
        }
        // `subtle` 对 `[u8]` 的 `ct_eq` 在长度不等时直接返回 `Choice::from(0)`，
        // 只有长度比较是短路的。CSRF 令牌长度是固定的公开参数（32 字节经
        // base64url 编码后恒为 43 字符），因此长度泄漏不构成风险；等长时的
        // 逐字节比较无数据相关分支。
        self.csrf_token.as_bytes().ct_eq(token.as_bytes()).into()
    }
}

fn idle_timeout_from_seconds(seconds: Option<u64>) -> Option<Duration> {
    seconds.filter(|&secs| secs > 0).map(Duration::from_secs)
}

fn idle_active_at(
    last_seen_at: OffsetDateTime,
    idle_timeout: Option<Duration>,
    now: OffsetDateTime,
) -> bool {
    idle_timeout
        .map(|timeout| idle_deadline(last_seen_at, timeout).is_some_and(|deadline| now < deadline))
        .unwrap_or(true)
}

fn idle_deadline(last_seen_at: OffsetDateTime, idle_timeout: Duration) -> Option<OffsetDateTime> {
    let timeout = TimeDuration::try_from(idle_timeout).ok()?;
    last_seen_at.checked_add(timeout)
}

pub fn generate_credential() -> SessionCredential {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let token_hash = session_token_hash_bytes(&token);
    SessionCredential { token, token_hash }
}

pub fn session_token_hash_bytes(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Base64url encoding used in OAuth payloads for the irreversible token digest.
pub fn session_token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(session_token_hash_bytes(token))
}

pub fn decode_session_token_hash(value: &str) -> Option<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    decoded.try_into().ok()
}

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;
