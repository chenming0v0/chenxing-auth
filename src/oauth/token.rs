use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::KeyManager;

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
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let decoding_key = keys.decoding_key().map_err(TokenError::Validation)?;
    let data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(TokenError::Validation)?;
    Ok(data.claims)
}

pub fn decode_userinfo_token(
    keys: &KeyManager,
    issuer: &str,
    token: &str,
) -> Result<AccessTokenClaims, TokenError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_aud = false;
    let decoding_key = keys.decoding_key().map_err(TokenError::Validation)?;
    let data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(TokenError::Validation)?;
    Ok(data.claims)
}

pub fn issue_access_token(
    keys: &KeyManager,
    issuer: &str,
    subject: &str,
    audience: &str,
    scopes: &[String],
    lifetime_seconds: u64,
) -> Result<String, TokenError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let now = usize::try_from(now).map_err(|_| TokenError::InvalidLifetime)?;
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
    header.kid = Some(keys.key_id().to_owned());
    encode(&header, &claims, keys.encoding_key()).map_err(TokenError::from)
}
