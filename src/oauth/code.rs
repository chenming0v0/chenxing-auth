use std::collections::BTreeMap;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    clock::{Clock, SystemClock},
    sessions::domain::session_token_hash,
};

/// 授权码默认有效期（秒）。运行时优先使用管理设置或启动配置覆盖。
/// 保留此常量作为无状态构造和补偿路径的向后兼容回退值。
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 5 * 60;

#[derive(Clone, Serialize)]
pub struct AuthorizationCode {
    pub value: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    /// 签发该授权码时所依赖的浏览器会话令牌 SHA-256 摘要。
    ///
    /// OIDC Core 3.1.3.2 与 AGENTS.md 都要求授权码绑定 Client、Redirect URI 和
    /// 用户会话：会话被撤销（用户登出）后，授权码必须立即失去兑换能力，否则
    /// 登出只是清了 Cookie，5 分钟 TTL 内的授权码仍能换出 access/refresh token。
    ///
    /// 摘要使用 base64url 无填充编码。直接构造的 `None` 只保留给不经过持久化兑换
    /// 的内部测试路径；从 Redis 兼容读取到缺失该字段的旧授权码会被单独标记，并在
    /// Token 端点 fail-closed，不能借兼容反序列化绕过会话校验。
    ///
    /// 反序列化 helper 的 `#[serde(default)]` + `skip_serializing_if` 是 Redis 兼容性要求，不可删除：
    /// - `default`：升级期间在途的旧授权码 JSON 没有这个键，仍允许读取以便稳定
    ///   返回 `invalid_grant`，但绝不允许兑换。
    /// - `skip_serializing_if`：保持旧载荷的稳定表示，便于混合版本部署；
    ///   `take_if_matches` 只比较已知协议字段，未知未来字段不参与 CAS。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token_hash: Option<String>,
    /// Compatibility marker set when an older Redis payload omitted the
    /// session binding field entirely. Such codes must fail closed at token
    /// exchange instead of using the intentional unbound-code fallback.
    #[serde(skip)]
    pub(crate) legacy_unbound_session_binding: bool,
    /// 签发时配额消耗对应的 reservation id（Issue #341）。
    ///
    /// 授权码过期未兑换时，后台 worker 凭这个 id 退还配额；兑换成功时
    /// `take_if_matches` 的 CAS 脚本在同一个原子步骤里把它对应的台账条目
    /// 取消。`None` 表示该授权码没有计量配额（admin Client、无生效套餐）。
    ///
    /// 序列化约定与 `session_token_hash` 相同：`#[serde(default)]` 保证升级
    /// 期间在途的旧授权码可读，`skip_serializing_if` 保持旧载荷表示稳定。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_reservation_id: Option<String>,
    /// Issuer generation captured from the request-scoped snapshot at issuance.
    ///
    /// Refresh Token already treats this as a hard trust-domain boundary
    /// (Issue #492). Authorization codes must do the same (Issue #516): a code
    /// minted under Issuer A must not redeem into tokens whose `iss` belongs to
    /// Issuer B after a hot switch. Missing/legacy payloads cannot prove their
    /// origin and fail closed at `/oauth/token` before CAS.
    ///
    /// Serialization matches `session_token_hash`: `#[serde(default)]` on the
    /// payload keeps in-flight Redis JSON readable; `skip_serializing_if`
    /// omits `None` so CAS still byte-compares known protocol fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_generation: Option<i64>,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCode")
            .field("value", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("user_id", &self.user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "quota_reservation_id",
                &self.quota_reservation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("issuer_generation", &self.issuer_generation)
            .field("scopes", &self.scopes)
            .field("code_challenge", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("redeemed_at", &self.redeemed_at)
            .finish()
    }
}

#[derive(Deserialize)]
struct AuthorizationCodePayload {
    value: String,
    client_id: String,
    redirect_uri: String,
    user_id: String,
    /// A missing (or explicitly null) field is treated as a legacy payload and
    /// marked for fail-closed handling during token exchange.
    #[serde(default)]
    session_token_hash: Option<Option<String>>,
    #[serde(default)]
    quota_reservation_id: Option<String>,
    #[serde(default)]
    issuer_generation: Option<i64>,
    scopes: Vec<String>,
    code_challenge: String,
    nonce: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    redeemed_at: Option<OffsetDateTime>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for AuthorizationCodePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCodePayload")
            .field("value", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("user_id", &self.user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "quota_reservation_id",
                &self.quota_reservation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("issuer_generation", &self.issuer_generation)
            .field("scopes", &self.scopes)
            .field("code_challenge", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("redeemed_at", &self.redeemed_at)
            // Legacy payloads may carry the former plaintext session token here.
            .field("extra", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for AuthorizationCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = AuthorizationCodePayload::deserialize(deserializer)?;
        // The old field held a plaintext session token. Reject it before any
        // store caller can reserialize the payload through CAS or restore.
        if payload.extra.contains_key("session_id") {
            return Err(DeError::custom(
                "authorization code contains an unsupported legacy session binding",
            ));
        }
        Ok(Self {
            value: payload.value,
            client_id: payload.client_id,
            redirect_uri: payload.redirect_uri,
            user_id: payload.user_id,
            legacy_unbound_session_binding: payload.session_token_hash.is_none(),
            session_token_hash: payload.session_token_hash.flatten(),
            quota_reservation_id: payload.quota_reservation_id,
            issuer_generation: payload.issuer_generation,
            scopes: payload.scopes,
            code_challenge: payload.code_challenge,
            nonce: payload.nonce,
            created_at: payload.created_at,
            expires_at: payload.expires_at,
            redeemed_at: payload.redeemed_at,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeError {
    #[error("authorization code has expired")]
    Expired,
    #[error("authorization code was already redeemed")]
    AlreadyRedeemed,
}

impl AuthorizationCode {
    pub fn new(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
    ) -> Self {
        Self::new_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            SystemClock.now(),
        )
    }

    pub fn new_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            None,
            None,
            now,
        )
    }

    /// Hashes the optional runtime session token before constructing the payload.
    pub fn new_with_nonce(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
    ) -> Self {
        Self::new_with_nonce_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token,
            SystemClock.now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token,
            AUTHORIZATION_CODE_TTL_SECONDS,
            now,
        )
    }

    /// 与 `new_with_nonce` 相同，但允许指定 TTL（#121：来自 `AppConfig::security_limits`）。
    // 授权码的元数据字段多，打包成结构体带来的名义上的"清晰度"不抵消每次调用
    // 都要构造临时结构体的冗余；客户端只有 authorization_code_handlers 一处，故维持现状。
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_and_ttl_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at_hashed(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token.map(|token| session_token_hash(&token)),
            ttl_seconds,
            now,
        )
    }

    /// Construct from a digest already carried by the validated OAuth request.
    ///
    /// 签发时刻由调用方传入（Token 授权路径经 `AppState` 的共享时钟），
    /// 保证 `created_at` / `expires_at` 与 store 保存时的 TTL 计算同源。
    /// `issuer_generation` 必须来自同一请求捕获的 Issuer 快照，不能在签发中途
    /// 重读 runtime。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_nonce_and_ttl_with_session_hash_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token_hash: Option<String>,
        ttl_seconds: u64,
        issuer_generation: i64,
        now: OffsetDateTime,
    ) -> Self {
        let mut code = Self::new_with_nonce_and_ttl_at_hashed(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token_hash,
            ttl_seconds,
            now,
        );
        code.issuer_generation = Some(issuer_generation);
        code
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_nonce_and_ttl_at_hashed(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token_hash: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            value: format!("cx-code-{}", Uuid::new_v4().simple()),
            client_id,
            redirect_uri,
            user_id,
            session_token_hash,
            legacy_unbound_session_binding: false,
            quota_reservation_id: None,
            issuer_generation: None,
            scopes,
            code_challenge,
            nonce,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds as i64),
            redeemed_at: None,
        }
    }

    pub fn redeem_at(&mut self, now: OffsetDateTime) -> Result<(), CodeError> {
        if self.redeemed_at.is_some() {
            return Err(CodeError::AlreadyRedeemed);
        }
        if now >= self.expires_at {
            return Err(CodeError::Expired);
        }
        self.redeemed_at = Some(now);
        Ok(())
    }

    /// Stamp the request-scoped Issuer generation. Test helpers that construct
    /// a code outside the authorization handler must call this before redeeming
    /// through `/oauth/token`; convenience constructors leave the field unset
    /// so missing/legacy payloads stay fail-closed.
    pub fn with_issuer_generation(mut self, generation: i64) -> Self {
        self.issuer_generation = Some(generation);
        self
    }

    /// Authorization codes belong to the Issuer generation that minted them.
    /// `None` is a pre-upgrade payload and fails closed, same as a mismatch.
    pub fn is_bound_to_issuer_generation(&self, current_generation: i64) -> bool {
        self.issuer_generation == Some(current_generation)
    }
}

#[cfg(test)]
#[path = "code_tests.rs"]
mod tests;
