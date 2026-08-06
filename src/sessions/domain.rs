use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::clock::{Clock, SystemClock};

/// 运行时会话结构，`token` 字段保存明文会话令牌。
///
/// 刻意不派生 `Serialize` / `Deserialize`：一旦可序列化，明文令牌就有可能被写进
/// 持久化载荷、日志或 API 响应。持久化统一走 [`SessionPayload`]，由类型系统保证
/// 明文令牌不会进入存储；新增字段时也不会因为忘记标注属性而重新泄露凭据。
#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPayload {
    pub id: i64,
    // token 字段被移除：它是明文凭据且在查询时被调用方传入值覆盖，持久化它没有必要且扩大了密钥泄露的影响面
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Hash-only session metadata returned when the caller has a token digest but
/// deliberately does not have the plaintext token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLookup {
    pub id: i64,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl SessionLookup {
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

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
            csrf_token: session.csrf_token.clone(),
            revoked_at: session.revoked_at,
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
            csrf_token: self.csrf_token,
            revoked_at: self.revoked_at,
        }
    }

    pub fn into_lookup(self) -> SessionLookup {
        SessionLookup {
            id: self.id,
            user_id: self.user_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCredential {
    pub token: String,
    pub token_hash: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session user id is empty")]
    EmptyUserId,
    #[error("session TTL must be greater than zero")]
    ZeroTtl,
}

impl Session {
    pub fn new(user_id: String, ttl: Duration) -> Result<Self, SessionError> {
        Self::new_at(user_id, ttl, SystemClock.now())
    }

    pub fn new_at(
        user_id: String,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> Result<Self, SessionError> {
        if user_id.trim().is_empty() {
            return Err(SessionError::EmptyUserId);
        }
        if ttl.is_zero() {
            return Err(SessionError::ZeroTtl);
        }
        let ttl = TimeDuration::try_from(ttl).map_err(|_| SessionError::ZeroTtl)?;
        let credential = generate_credential();
        let mut csrf_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        Ok(Self {
            id: 0,
            token: credential.token,
            user_id,
            created_at: now,
            expires_at: now + ttl,
            csrf_token: URL_SAFE_NO_PAD.encode(csrf_bytes),
            revoked_at: None,
        })
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    pub fn revoke(&mut self) {
        self.revoke_at(SystemClock.now());
    }

    pub fn revoke_at(&mut self, now: OffsetDateTime) {
        self.revoked_at = Some(now);
    }

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
mod tests {
    use super::{
        Session, SessionPayload, decode_session_token_hash, generate_credential,
        session_token_hash, session_token_hash_bytes,
    };
    use std::time::Duration;
    use time::OffsetDateTime;

    #[test]
    fn credentials_are_random_and_hashable_without_exposing_plaintext() {
        let first = generate_credential();
        let second = generate_credential();
        assert_ne!(first.token, second.token);
        assert_eq!(first.token.len(), 43);
        assert_ne!(first.token_hash, [0; 32]);
    }

    #[test]
    fn session_token_hash_uses_a_fixed_digest_encoding() {
        let token = "session-token";
        let encoded = session_token_hash(token);

        assert_ne!(encoded, token);
        assert_eq!(encoded.len(), 43);
        assert_eq!(
            decode_session_token_hash(&encoded),
            Some(session_token_hash_bytes(token))
        );
    }

    #[test]
    fn new_session_starts_without_an_internal_database_id() {
        let session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
        assert_eq!(session.id, 0);
        assert!(!session.token.is_empty());
    }

    #[test]
    fn new_session_uses_the_supplied_creation_time() {
        let created_at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(123);
        let session =
            Session::new_at("1".to_owned(), Duration::from_secs(60), created_at).unwrap();

        assert_eq!(session.created_at, created_at);
        assert_eq!(
            session.expires_at,
            created_at + time::Duration::seconds(60)
        );
    }

    /// 43 字符的 base64url 令牌，与 `Session::new` 生成的 CSRF 令牌长度一致。
    const CSRF_TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn session_with_csrf(csrf_token: &str) -> Session {
        let mut session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
        session.csrf_token = csrf_token.to_owned();
        session
    }

    /// 常量时间比较的注释假设 CSRF 令牌长度是固定的公开参数，这里锁定该不变量。
    #[test]
    fn generated_csrf_token_has_a_fixed_public_length() {
        let session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
        assert_eq!(session.csrf_token.len(), 43);
        assert_eq!(CSRF_TOKEN.len(), session.csrf_token.len());
    }

    #[test]
    fn csrf_validation_accepts_the_matching_token() {
        let session = session_with_csrf(CSRF_TOKEN);
        assert!(session.validates_csrf(CSRF_TOKEN));
    }

    #[test]
    fn csrf_validation_rejects_a_different_token_of_the_same_length() {
        let session = session_with_csrf(CSRF_TOKEN);
        assert!(!session.validates_csrf("GFEDCBA9876543210zyxwvutsrqponmlkjihgfedcba"));
    }

    #[test]
    fn csrf_validation_rejects_an_empty_token() {
        let session = session_with_csrf(CSRF_TOKEN);
        assert!(!session.validates_csrf(""));
    }

    #[test]
    fn csrf_validation_rejects_an_empty_token_even_when_the_session_has_none() {
        // 会话侧令牌异常缺失时，空头部也不能被判定为相等。
        let session = session_with_csrf("");
        assert!(!session.validates_csrf(""));
    }

    #[test]
    fn csrf_validation_rejects_tokens_with_a_different_length() {
        let session = session_with_csrf(CSRF_TOKEN);
        assert!(!session.validates_csrf(&CSRF_TOKEN[..CSRF_TOKEN.len() - 1]));
        assert!(!session.validates_csrf(&format!("{CSRF_TOKEN}H")));
    }

    /// 校验不是前缀匹配：只差首字符或末字符都必须拒绝。
    #[test]
    fn csrf_validation_rejects_tokens_differing_in_a_single_character() {
        let session = session_with_csrf(CSRF_TOKEN);
        let mut last_differs = CSRF_TOKEN.to_owned();
        last_differs.pop();
        last_differs.push('H');
        assert!(!session.validates_csrf(&last_differs));

        let first_differs = format!("X{}", &CSRF_TOKEN[1..]);
        assert_eq!(first_differs.len(), CSRF_TOKEN.len());
        assert!(!session.validates_csrf(&first_differs));
    }

    /// 构造升级前的载荷 JSON：`SessionPayload` 的字段加上当时存在的明文 `token`。
    ///
    /// 不写死时间戳字面量——`time` 只启用了 `serde` 特性（没有 `serde-human-readable`），
    /// `OffsetDateTime` 的序列化形式不是 RFC 3339 字符串，硬编码字面量会与实际格式失配。
    fn legacy_payload_json(session: &Session) -> String {
        let mut value =
            serde_json::to_value(SessionPayload::from(session)).expect("payload as JSON value");
        value
            .as_object_mut()
            .expect("payload serializes to a JSON object")
            .insert(
                "token".to_owned(),
                serde_json::Value::String(session.token.clone()),
            );
        value.to_string()
    }

    /// 载荷不得携带明文会话令牌：密钥与数据库备份同时泄露时，
    /// 攻击者只能拿到 token_hash，无法反推出可用令牌。
    #[test]
    fn serialized_payload_never_contains_the_plaintext_session_token() {
        let session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
        let payload = SessionPayload::from(&session);

        let value = serde_json::to_value(&payload).expect("payload as JSON value");
        assert!(value.get("token").is_none());
        assert!(
            !serde_json::to_string(&payload)
                .expect("serialize payload")
                .contains(&session.token)
        );
        // csrf_token 必须继续持久化：find() 依赖它完成双提交校验。
        assert_eq!(
            value.get("csrf_token").and_then(serde_json::Value::as_str),
            Some(session.csrf_token.as_str())
        );
    }

    /// 向后兼容回归：升级前写入的载荷含 `token` 字段。`SessionPayload` 未标注
    /// `deny_unknown_fields`，serde 必须忽略这个多余字段而不是报错，
    /// 否则升级后所有历史会话都会解析失败而被判定为不存在。
    #[test]
    fn legacy_payload_containing_a_token_field_is_still_readable() {
        let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
        session.id = 7;
        let legacy_json = legacy_payload_json(&session);
        // 前置条件：构造出的旧载荷确实含明文令牌，否则这个回归测试没有意义。
        assert!(legacy_json.contains(&session.token));

        let payload: SessionPayload =
            serde_json::from_str(&legacy_json).expect("legacy payload must remain readable");

        assert_eq!(payload.id, 7);
        assert_eq!(payload.user_id, "42");
        assert_eq!(payload.csrf_token, session.csrf_token);
        assert_eq!(payload.created_at, session.created_at);
        assert_eq!(payload.expires_at, session.expires_at);
        assert!(payload.revoked_at.is_none());

        // 令牌只从请求来：旧载荷里的明文令牌被忽略，由调用方传入值填回。
        let restored = payload.into_session("token-from-request".to_owned());
        assert_eq!(restored.token, "token-from-request");
        assert_ne!(restored.token, session.token);
        assert!(restored.validates_csrf(&session.csrf_token));
    }

    /// 归一化后的旧载荷不再含明文令牌。outbox 投影到 Redis 走的是同一条
    /// 「解析 + 重新序列化」路径，因此历史会话也不会在 Redis 留下可用令牌。
    #[test]
    fn legacy_payload_loses_its_token_when_reserialized() {
        let session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
        let legacy_json = legacy_payload_json(&session);
        let payload: SessionPayload = serde_json::from_str(&legacy_json).expect("legacy payload");

        let reserialized = serde_json::to_value(&payload).expect("reserialize payload");

        assert!(reserialized.get("token").is_none());
        assert!(!reserialized.to_string().contains(&session.token));
        assert_eq!(
            reserialized
                .get("csrf_token")
                .and_then(serde_json::Value::as_str),
            Some(session.csrf_token.as_str())
        );
    }

    /// 存储往返：除令牌外的字段必须原样恢复，令牌由调用方补回。
    #[test]
    fn payload_round_trip_restores_every_field_except_the_token() {
        let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
        session.id = 99;
        let original = session.clone();

        let encoded = serde_json::to_vec(&SessionPayload::from(&session)).expect("serialize");
        let decoded: SessionPayload = serde_json::from_slice(&encoded).expect("deserialize");
        let restored = decoded.into_session(original.token.clone());

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.token, original.token);
        assert_eq!(restored.user_id, original.user_id);
        assert_eq!(restored.created_at, original.created_at);
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.csrf_token, original.csrf_token);
        assert_eq!(restored.revoked_at, original.revoked_at);
        assert!(restored.validates_csrf(&original.csrf_token));
    }

    /// 撤销时间戳属于持久化事实，必须往返保留。
    #[test]
    fn payload_round_trip_preserves_the_revocation_timestamp() {
        let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
        session.revoke();

        let encoded = serde_json::to_vec(&SessionPayload::from(&session)).expect("serialize");
        let decoded: SessionPayload = serde_json::from_slice(&encoded).expect("deserialize");

        assert_eq!(decoded.revoked_at, session.revoked_at);
        assert!(!decoded.into_session(session.token.clone()).is_active());
    }
}
