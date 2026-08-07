use jsonwebtoken::{Algorithm, Header, encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use crate::keys::{KeyManager, KeyManagerError};

#[derive(Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    /// 终端用户完成认证的时刻（OIDC Core 1.0 §2）。
    ///
    /// 取值是会话建立时间，不是 `iat`：`iat` 是 ID Token 签发时刻，二者在
    /// 「登录后一段时间才授权」的场景相差可以很大，混用会让依赖 `max_age`
    /// 的 RP 判断错误。
    ///
    /// 无会话上下文时（授权码降级路径、刷新令牌流程）省略该键而不是写 `null`：
    /// OIDC Core 5.1 规定「不返回的 Claim 应当省略」，`null` 会让严格的 RP
    /// 客户端库解析失败。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("auth_time", &self.auth_time)
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("email", &self.email)
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct IdTokenProfile<'a> {
    pub nonce: Option<&'a str>,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    /// 会话建立时间的 Unix 秒，`None` 表示没有会话上下文，`auth_time` 将被省略。
    pub auth_time: Option<i64>,
}

impl fmt::Debug for IdTokenProfile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdTokenProfile")
            .field("nonce", &self.nonce.map(|_| "<redacted>"))
            .field("email", &self.email)
            .field("name", &self.name)
            .field("auth_time", &self.auth_time)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum IdTokenError {
    #[error("ID token lifetime is invalid")]
    InvalidLifetime,
    #[error("ID token signing failed: {0}")]
    Signing(#[from] jsonwebtoken::errors::Error),
    #[error("signing key state unavailable: {0}")]
    KeyState(#[from] KeyManagerError),
}

pub fn issue_id_token(
    keys: &KeyManager,
    issuer: &str,
    subject: &str,
    audience: &str,
    nonce: Option<&str>,
    lifetime_seconds: u64,
) -> Result<String, IdTokenError> {
    issue_id_token_with_profile(
        keys,
        issuer,
        subject,
        audience,
        IdTokenProfile {
            nonce,
            ..Default::default()
        },
        lifetime_seconds,
    )
}

pub fn issue_id_token_with_profile(
    keys: &KeyManager,
    issuer: &str,
    subject: &str,
    audience: &str,
    profile: IdTokenProfile<'_>,
    lifetime_seconds: u64,
) -> Result<String, IdTokenError> {
    let now = usize::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| IdTokenError::InvalidLifetime)?;
    let lifetime = usize::try_from(lifetime_seconds).map_err(|_| IdTokenError::InvalidLifetime)?;
    let exp = now
        .checked_add(lifetime)
        .ok_or(IdTokenError::InvalidLifetime)?;
    let claims = IdTokenClaims {
        iss: issuer.trim_end_matches('/').to_owned(),
        sub: subject.to_owned(),
        aud: audience.to_owned(),
        exp,
        iat: now,
        // 负数或超范围的时间戳只可能来自损坏数据；这种情况省略该 Claim，
        // 不要签出一个错误的 auth_time。
        auth_time: profile
            .auth_time
            .and_then(|value| usize::try_from(value).ok()),
        nonce: profile.nonce.map(str::to_owned),
        email: profile.email.map(str::to_owned),
        name: profile.name.map(str::to_owned),
    };
    let mut header = Header::new(Algorithm::RS256);
    let signing_key = keys.active_signing_key().map_err(IdTokenError::KeyState)?;
    header.kid = Some(signing_key.key_id().to_owned());
    encode(&header, &claims, signing_key.encoding_key()).map_err(IdTokenError::from)
}
