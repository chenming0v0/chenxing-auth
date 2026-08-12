use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    clock::{Clock, SystemClock},
    keys::KeyManager,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub scope: String,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token signing failed: {0}")]
    Signing(#[from] jsonwebtoken::errors::Error),
    #[error("token lifetime is invalid")]
    InvalidLifetime,
    #[error("token validation failed: {0}")]
    Validation(jsonwebtoken::errors::Error),
}

pub fn decode_access_token(
    keys: &KeyManager,
    issuer: &str,
    audience: &str,
    token: &str,
) -> Result<AccessTokenClaims, TokenError> {
    decode_with_validation(keys, issuer, audience, token, true)
}

pub fn decode_userinfo_token(
    keys: &KeyManager,
    issuer: &str,
    token: &str,
) -> Result<AccessTokenClaims, TokenError> {
    decode_with_validation(keys, issuer, "", token, false)
}

fn decode_with_validation(
    keys: &KeyManager,
    issuer: &str,
    audience: &str,
    token: &str,
    validate_audience: bool,
) -> Result<AccessTokenClaims, TokenError> {
    let header = jsonwebtoken::decode_header(token).map_err(TokenError::Validation)?;
    let key_id = header.kid.as_deref().ok_or_else(invalid_token_error)?;
    let mut validation = Validation::new(Algorithm::RS256);
    // Access and UserInfo tokens are revoked at their protocol expiry; do not inherit
    // jsonwebtoken's 60-second default clock-skew window.
    validation.leeway = 0;
    validation.set_issuer(&[issuer.trim_end_matches('/')]);
    validation.validate_aud = validate_audience;
    if validate_audience {
        validation.set_audience(&[audience]);
    }
    // 未发布的 `kid` 是协议层结果（令牌无效），不是服务端故障：验证只读内存快照，
    // 没有磁盘或锁竞争可言，因此这里不存在需要区分的 5xx 分支（Issue #257）。
    let decoding_key = keys
        .verification_key_for(key_id)
        .ok_or_else(|| TokenError::Validation(invalid_token_error()))?;
    let data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(TokenError::Validation)?;
    Ok(data.claims)
}

fn invalid_token_error() -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
}

/// 用进程默认时钟签发 Access Token。
///
/// 生产的 Token 端点走 [`issue_access_token_at`] 并传入 `AppState` 的共享时钟；
/// 这个包装保留给不持有 `AppState` 的调用点（密钥轮换测试、独立签名工具）。
pub fn issue_access_token(
    keys: &KeyManager,
    issuer: &str,
    subject: &str,
    audience: &str,
    scopes: &[String],
    lifetime_seconds: u64,
) -> Result<String, TokenError> {
    issue_access_token_at(
        keys,
        issuer,
        subject,
        audience,
        scopes,
        lifetime_seconds,
        SystemClock.now(),
    )
}

/// 以显式签发时刻签发 Access Token。
///
/// `iat` / `exp` 都由 `now` 派生，因此固定时钟可以精确构造「刚好过期」和
/// 「还差一秒过期」两种令牌，用于验证端点的过期判定。
pub fn issue_access_token_at(
    keys: &KeyManager,
    issuer: &str,
    subject: &str,
    audience: &str,
    scopes: &[String],
    lifetime_seconds: u64,
    now: time::OffsetDateTime,
) -> Result<String, TokenError> {
    let now = usize::try_from(now.unix_timestamp()).map_err(|_| TokenError::InvalidLifetime)?;
    let lifetime = usize::try_from(lifetime_seconds).map_err(|_| TokenError::InvalidLifetime)?;
    let claims = AccessTokenClaims {
        iss: issuer.trim_end_matches('/').to_owned(),
        sub: subject.to_owned(),
        aud: audience.to_owned(),
        exp: now
            .checked_add(lifetime)
            .ok_or(TokenError::InvalidLifetime)?,
        iat: now,
        scope: scopes.join(" "),
    };
    let mut header = Header::new(Algorithm::RS256);
    let signing_key = keys.active_signing_key();
    header.kid = Some(signing_key.key_id().to_owned());
    encode(&header, &claims, signing_key.encoding_key()).map_err(TokenError::from)
}
