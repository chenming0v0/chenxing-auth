use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
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
        if user_id.trim().is_empty() {
            return Err(SessionError::EmptyUserId);
        }
        if ttl.is_zero() {
            return Err(SessionError::ZeroTtl);
        }
        let created_at = OffsetDateTime::now_utc();
        let ttl = TimeDuration::try_from(ttl).map_err(|_| SessionError::ZeroTtl)?;
        let credential = generate_credential();
        let mut csrf_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        Ok(Self {
            id: 0,
            token: credential.token,
            user_id,
            created_at,
            expires_at: created_at + ttl,
            csrf_token: URL_SAFE_NO_PAD.encode(csrf_bytes),
            revoked_at: None,
        })
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    pub fn revoke(&mut self) {
        self.revoked_at = Some(OffsetDateTime::now_utc());
    }

    pub fn is_active(&self) -> bool {
        self.is_active_at(OffsetDateTime::now_utc())
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
    let token_hash = Sha256::digest(token.as_bytes()).into();
    SessionCredential { token, token_hash }
}

#[cfg(test)]
mod tests {
    use super::{Session, generate_credential};
    use std::time::Duration;

    #[test]
    fn credentials_are_random_and_hashable_without_exposing_plaintext() {
        let first = generate_credential();
        let second = generate_credential();
        assert_ne!(first.token, second.token);
        assert_eq!(first.token.len(), 43);
        assert_ne!(first.token_hash, [0; 32]);
    }

    #[test]
    fn new_session_starts_without_an_internal_database_id() {
        let session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
        assert_eq!(session.id, 0);
        assert!(!session.token.is_empty());
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
}
