use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::clock::{Clock, SystemClock};

/// 计算 Refresh Token 值的 SHA-256 + URL-safe base64 哈希。
///
/// 原始 token 值不进入 Redis keyspace、索引成员或日志，避免 keyspace dump 或
/// 慢查询日志泄露可用凭据。`refresh_store` 的主键、索引与墓碑键共用此函数，
/// 与 `revocation.rs` / `sessions::store` 的既有哈希约定保持一致。
pub(crate) fn refresh_token_hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// Refresh Token 的绝对有效期上限（RFC 9700 §4.14.2 建议限制长期凭据的生命周期）。
///
/// 即使客户端在滑动窗口内持续轮换，凭据的总生命周期也不得超过此值，
/// 防止多年前被窃取的 token 因持续使用而永不失效（Issue #109）。
///
/// 当前硬编码 180 天；后续应收敛进 `AppConfig` 以支持运维调整。
/// `refresh_store` 和 consent revocation cache 都从此常量派生 Redis TTL，
/// 避免各处分别写死 180 天。
pub const REFRESH_TOKEN_ABSOLUTE_TTL_DAYS: i64 = 180;

/// Refresh Token 的滑动过期窗口（每次轮换后重新计时）。
pub const REFRESH_TOKEN_SLIDING_TTL_DAYS: i64 = 30;

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub value: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// 凭据的首次签发时刻（RFC 9700 §4.14.2：绝对有效期的起点）。
    ///
    /// 轮换时不变，用于计算凭据家族的总生命周期。旧格式 token 缺失此字段时，
    /// 反序列化为 `None`，`issued_at()` 方法会回退到 `created_at`（保守兼容）。
    ///
    /// `skip_serializing_if` 保持旧 token 的序列化表示稳定；存储层 CAS 只比较
    /// 已知协议字段，未知未来字段不会导致轮换失败。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<OffsetDateTime>,
    /// Token Family ID（RFC 9700 §4.14.2：检测重放攻击的撤销单元）。
    ///
    /// 同一授权流程产生的所有轮换后继 token 共享同一 family_id。检测到任意
    /// 成员被重放时，撤销整个家族（攻击者和合法客户端各持一个轮换后的 token，
    /// 只拒绝当次请求会让攻击者继续用手里那个）。
    ///
    /// 旧格式 token 缺失时反序列化为空字符串；首次轮换时家族由 token 值哈希
    /// 确定性派生（`legacy-token:{hash}`，见 [`Self::family_identifier`]），
    /// 与存储层对空 family 的撤销域回退是同一个键空间，因此无论从活 payload、
    /// 墓碑还是轮换后继定位，撤销都命中同一家族（Issue #313）。
    ///
    /// `skip_serializing_if` 保持旧 token 的表示稳定（同 `issued_at` 约束）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_id: String,
    /// Client Secret generation that authenticated the original issuance.
    ///
    /// Every successor inherits this value. A token is redeemable only when it
    /// matches the generation authenticated by the current request, so a token
    /// left behind by a failed best-effort revocation is still inert after a
    /// Secret rotation. Legacy payloads predate the field; they are accepted
    /// under the currently authenticated generation and stamped on their first
    /// rotation so an upgrade does not revoke otherwise healthy grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_version: Option<i64>,
    /// 签发时用户 `users.session_epoch` 的快照（Issue #409）。
    ///
    /// `session_epoch` 是「撤销该用户全部凭据」的单一水位：改密、管理端 TOTP
    /// 重置、禁用账号都通过 `revoke_all_for_user_in_transaction` 推进它，会话
    /// 校验在每次查找时已经按它过滤（`sessions.session_epoch >= users.session_epoch`），
    /// 而 Refresh Token 此前完全没有这道判定——TOTP 重置只踢掉 Cookie 会话，
    /// 旧 Refresh Token 仍能持续换取 access token。签发时把 epoch 绑定进凭据，
    /// 兑换时与当前值比对，任何推进 epoch 的撤销操作都会让该用户此前签发的
    /// 全部 Refresh Token 立即失效。
    ///
    /// 轮换时**继承**而不是重新读取当前值：重新读取会让「兑换检查通过之后、
    /// 轮换落地之前」发生的撤销被新 stamp 抹掉，等于把重置后的第一个兑换
    /// 重新救活。同一 grant 的后继凭据必须属于同一代。
    ///
    /// 旧格式 payload 缺失此字段时反序列化为 `None`。`None` 在兑换路径
    /// fail-closed（拒绝）：无法证明签发时刻的凭据不能继续信任，升级后
    /// 客户端重新走一次授权流程换取新代际凭据即可。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_epoch: Option<i64>,
    /// Refresh Token 签发时的 Issuer 配置代际（Issue #492）。
    ///
    /// Issuer 热切换会改变后续 Access Token / ID Token 的 `iss`。如果不把
    /// Refresh Token 绑定到签发时的 generation，旧 Issuer 下取得的长期凭据
    /// 就能在新 Issuer 下继续兑换，等价于跨越了两个独立的信任域。兑换必须与
    /// 当前请求捕获的 [`IssuerSnapshot`](crate::settings::IssuerSnapshot) 严格比对。
    ///
    /// 轮换后继继承该值，不能重新 stamp 当前 generation；否则一次旧代际兑换
    /// 会把整个 grant 洗到新 Issuer。旧 payload 缺失该字段时无法证明来源，
    /// 因此兑换路径 fail-closed，要求客户端重新走授权流程。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_generation: Option<i64>,
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshToken")
            .field("value", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("user_id", &self.user_id)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("issued_at", &self.issued_at)
            .field("family_id", &self.family_id)
            .field("client_secret_version", &self.client_secret_version)
            .field("session_epoch", &self.session_epoch)
            .field("issuer_generation", &self.issuer_generation)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::RefreshToken;
    use time::{Duration, OffsetDateTime};

    #[test]
    fn explicit_time_constructor_and_rotation_are_deterministic() {
        let created_at = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let token = RefreshToken::new_at_with_client_secret_version(
            "client".to_owned(),
            "user".to_owned(),
            vec!["openid".to_owned()],
            7,
            3,
            11,
            created_at,
        );
        let rotated_at = created_at + Duration::days(2);
        let rotated = token.rotate_at(vec!["profile".to_owned()], rotated_at);

        assert_eq!(token.created_at, created_at);
        assert_eq!(rotated.created_at, rotated_at);
        assert_eq!(rotated.issued_at, token.issued_at);
        assert_eq!(rotated.family_id, token.family_id);
        assert_eq!(rotated.client_secret_version, token.client_secret_version);
        // Issue #409：凭据代际必须由轮换继承，轮换不能重新读取当前 epoch，
        // 否则撤销与轮换的竞态会把已撤销的 grant 重新救活。
        assert_eq!(rotated.session_epoch, token.session_epoch);
        assert_eq!(rotated.issuer_generation, token.issuer_generation);
    }

    /// Issue #313：旧格式 token（空 `family_id`）轮换后，后继必须留在由旧值
    /// 哈希派生的家族里，让撤销/重放路径从任何入口（活 payload、墓碑、CAS
    /// 陈旧 payload）都能命中它，而不是落入全新家族。
    #[test]
    fn legacy_token_rotation_stays_in_the_derived_family() {
        let created_at = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let mut token = RefreshToken::new_at_with_client_secret_version(
            "client".to_owned(),
            "user".to_owned(),
            vec!["openid".to_owned()],
            7,
            3,
            11,
            created_at,
        );
        // 模拟旧格式 payload：family_id 缺失，反序列化为空串。
        token.family_id.clear();

        let rotated = token.rotate_at(vec!["openid".to_owned()], created_at + Duration::days(2));

        assert!(!rotated.family_id.is_empty());
        assert_eq!(rotated.family_id, token.family_identifier());
        assert_eq!(
            rotated.family_id,
            format!("legacy-token:{}", super::refresh_token_hash(&token.value))
        );
        // 家族随轮换链一路继承，后续轮换不再派生新家族。
        let second = rotated.rotate_at(vec!["openid".to_owned()], created_at + Duration::days(3));
        assert_eq!(second.family_id, rotated.family_id);
    }

    /// Issue #492：Issuer generation 是严格的信任域边界。旧 payload 的缺失值
    /// 和其它 generation 都不能被当作当前 Issuer 的凭据。
    #[test]
    fn issuer_generation_binding_is_strict_and_legacy_payloads_fail_closed() {
        let mut token = RefreshToken::new_at_with_client_secret_version(
            "client".to_owned(),
            "user".to_owned(),
            vec!["openid".to_owned()],
            7,
            3,
            11,
            OffsetDateTime::UNIX_EPOCH + Duration::days(1),
        );

        assert!(token.is_bound_to_issuer_generation(11));
        assert!(!token.is_bound_to_issuer_generation(12));

        token.issuer_generation = None;
        assert!(!token.is_bound_to_issuer_generation(11));
        assert_eq!(
            token
                .rotate_at(
                    vec!["openid".to_owned()],
                    OffsetDateTime::UNIX_EPOCH + Duration::days(2),
                )
                .issuer_generation,
            None,
            "rotation must never upgrade an unbound legacy token into the current issuer"
        );
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RefreshTokenError {
    #[error("refresh token is expired")]
    Expired,
    #[error("refresh token is revoked")]
    Revoked,
    #[error("refresh token is not bound to client")]
    ClientMismatch,
    #[error("refresh token has exceeded its absolute lifetime")]
    AbsoluteLifetimeExceeded,
}

impl RefreshToken {
    /// 墙钟便捷入口，只给测试和夹具用。
    ///
    /// 生产签发必须走 [`Self::new_at`] / [`Self::new_at_with_client_secret_version`]
    /// 并传入注入的 `SharedClock`，让 TTL 和过期共用同一时间源（Issue #366）。
    pub fn new(client_id: String, user_id: String, scopes: Vec<String>) -> Self {
        Self::new_at(client_id, user_id, scopes, SystemClock.now())
    }

    pub fn new_at(
        client_id: String,
        user_id: String,
        scopes: Vec<String>,
        now: OffsetDateTime,
    ) -> Self {
        // 测试便捷构造：绑定到 epoch 0（注册接口创建的用户默认从 0 开始）。
        // 需要精确控制凭据代际的测试应使用完整构造器。
        Self::new_at_with_client_secret_version(client_id, user_id, scopes, 0, 0, 0, now)
    }

    /// Construct a token bound to the Client credential snapshot, the user's
    /// current `session_epoch`, and the request-scoped Issuer generation that
    /// passed the token endpoint gates. Every binding is checked again on
    /// refresh; successors inherit all three generations.
    pub fn new_at_with_client_secret_version(
        client_id: String,
        user_id: String,
        scopes: Vec<String>,
        client_secret_version: i64,
        session_epoch: i64,
        issuer_generation: i64,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            value: format!("cx-refresh-{}", Uuid::new_v4().simple()),
            client_id,
            user_id,
            scopes,
            created_at: now,
            expires_at: now + Duration::days(REFRESH_TOKEN_SLIDING_TTL_DAYS),
            revoked_at: None,
            issued_at: Some(now),
            family_id: Uuid::new_v4().simple().to_string(),
            client_secret_version: Some(client_secret_version),
            session_epoch: Some(session_epoch),
            issuer_generation: Some(issuer_generation),
        }
    }

    /// 轮换 token（RFC 9700 §4.14.2：旧 token 单次使用，返回新 token）。
    ///
    /// 继承 `issued_at` 和 `family_id` 以维持家族关系和绝对生命周期；
    /// 更新 `created_at` / `expires_at` 以重置滑动窗口。旧格式 token 的
    /// 家族由 token 值确定性派生（[`Self::family_identifier`]），使轮换后继
    /// 仍留在原 token 的撤销域内（Issue #313）。
    ///
    /// 墙钟便捷入口，只给测试和夹具用。生产刷新路径必须走
    /// [`Self::rotate_at`] / [`Self::rotate_at_with_client_secret_version`]，
    /// 并传入与 `validate`、Redis TTL 相同的时刻（Issue #366）。
    pub fn rotate(&self, scopes: Vec<String>) -> Self {
        self.rotate_at(scopes, SystemClock.now())
    }

    pub fn rotate_at(&self, scopes: Vec<String>, now: OffsetDateTime) -> Self {
        let issued_at = self.issued_at();
        let absolute_deadline = self.absolute_deadline();
        let sliding_deadline = now + Duration::days(REFRESH_TOKEN_SLIDING_TTL_DAYS);
        Self {
            value: format!("cx-refresh-{}", Uuid::new_v4().simple()),
            client_id: self.client_id.clone(),
            user_id: self.user_id.clone(),
            scopes,
            created_at: now,
            // 取滑动窗口与绝对截止的较早值，保证不会超出绝对上限
            expires_at: sliding_deadline.min(absolute_deadline),
            revoked_at: None,
            issued_at: Some(issued_at),
            family_id: self.family_identifier(),
            client_secret_version: self.client_secret_version,
            session_epoch: self.session_epoch,
            issuer_generation: self.issuer_generation,
        }
    }

    /// Rotate and bind a legacy or current token to the Client Secret generation
    /// authenticated by the token endpoint. This method deliberately does not
    /// stamp an Issuer generation: that binding is inherited by `rotate_at`, and
    /// an unbound legacy payload must remain unbound so the use case rejects it.
    pub fn rotate_at_with_client_secret_version(
        &self,
        scopes: Vec<String>,
        client_secret_version: i64,
        now: OffsetDateTime,
    ) -> Self {
        let mut rotated = self.rotate_at(scopes, now);
        rotated.client_secret_version = Some(client_secret_version);
        rotated
    }

    /// Legacy payloads have no generation to compare. A database compatibility
    /// bit admits them only until the Client's first post-upgrade Secret
    /// rotation; their successor is always stamped.
    pub fn is_bound_to_client_secret_version(
        &self,
        expected_version: i64,
        allow_legacy_refresh_tokens: bool,
    ) -> bool {
        match self.client_secret_version {
            Some(version) => version == expected_version,
            None => allow_legacy_refresh_tokens,
        }
    }

    /// 校验凭据代际（Issue #409）：token 签发时 stamp 的 `session_epoch` 必须
    /// 等于用户当前值。`session_epoch` 是「撤销该用户全部凭据」的单一水位——
    /// 改密、管理端 TOTP 重置、禁用账号都推进它，会话校验每次查找都在比对
    /// （`sessions.session_epoch >= users.session_epoch`），Refresh Token 也必须
    /// 一样。不一致说明签发后发生过撤销操作，凭据必须失效；旧格式 payload
    /// 没有 epoch、无法证明签发时刻，同样 fail-closed 拒绝。
    pub fn is_bound_to_session_epoch(&self, current_epoch: i64) -> bool {
        self.session_epoch == Some(current_epoch)
    }

    /// 校验 Refresh Token 是否属于当前请求捕获的 Issuer 代际（Issue #492）。
    ///
    /// `None` 代表升级前 payload；与不匹配的 generation 一样 fail-closed。
    /// 调用方必须使用请求入口注入的快照，不能在兑换中途重读 runtime，否则
    /// 同一请求可能混用两个 Issuer 代际。
    pub fn is_bound_to_issuer_generation(&self, current_generation: i64) -> bool {
        self.issuer_generation == Some(current_generation)
    }

    /// 返回凭据的首次签发时刻（绝对有效期计算的起点）。
    ///
    /// 旧格式 token 缺失 `issued_at` 时回退到 `created_at`（保守兼容：
    /// 假定该 token 就是原始签发，而非已轮换多次的后继）。
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at.unwrap_or(self.created_at)
    }

    /// 旧格式 token（空 `family_id`）的家族标识：由 token 值哈希确定性派生。
    ///
    /// 派生值 `legacy-token:{hash}` 与存储层 `FamilyScope` 对空 family 的
    /// 回退后缀完全一致，因此活 token 撤销、墓碑撤销和 CAS 陈旧 payload
    /// 三条路径解析到的都是同一个撤销域。
    pub fn legacy_family_id(&self) -> String {
        format!("legacy-token:{}", refresh_token_hash(&self.value))
    }

    /// 撤销/重放路径使用的家族标识（RFC 9700 §4.14.2 的撤销单元）。
    ///
    /// 新格式 token 返回存储的 `family_id`；旧格式（空串）返回
    /// [`Self::legacy_family_id`] 的派生值。
    pub fn family_identifier(&self) -> String {
        Self::resolve_family_identifier(&self.family_id, &self.value)
    }

    /// 把存储态（payload / 墓碑）里的 `family_id` 解析为撤销路径的家族标识。
    ///
    /// 新格式直接返回；旧格式（空串，包括升级前写入的旧墓碑）由 token 值
    /// 哈希派生，保证撤销/重放定位到的家族与轮换后继一致（Issue #313）。
    pub fn resolve_family_identifier(family_id: &str, token_value: &str) -> String {
        if family_id.is_empty() {
            format!("legacy-token:{}", refresh_token_hash(token_value))
        } else {
            family_id.to_owned()
        }
    }

    /// 返回凭据家族的绝对截止时刻（首次签发 + 180 天）。
    ///
    /// `validate`、`rotate` 和 `refresh_store` 的 TTL 计算共用此方法，
    /// 避免三处各自重复「issued_at + 180 天」的算式。
    pub fn absolute_deadline(&self) -> OffsetDateTime {
        self.issued_at() + Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS)
    }

    /// 校验 token 的客户端绑定、撤销状态、滑动过期和绝对生命周期。
    pub fn validate(&self, client_id: &str, now: OffsetDateTime) -> Result<(), RefreshTokenError> {
        if self.client_id != client_id {
            return Err(RefreshTokenError::ClientMismatch);
        }
        if self.revoked_at.is_some() {
            return Err(RefreshTokenError::Revoked);
        }
        // 滑动过期检查（30 天未使用）
        if now >= self.expires_at {
            return Err(RefreshTokenError::Expired);
        }
        // 绝对生命周期检查（首次签发后 180 天，RFC 9700 §4.14.2）。
        // 即使轮换让 expires_at 一直向后滑动，这里也会拒绝超龄凭据（Issue #109）。
        if now >= self.absolute_deadline() {
            return Err(RefreshTokenError::AbsoluteLifetimeExceeded);
        }
        Ok(())
    }

    pub fn is_valid_for(&self, client_id: &str, now: OffsetDateTime) -> bool {
        self.validate(client_id, now).is_ok()
    }
}
