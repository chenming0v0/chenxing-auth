use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{KeyManager, KeyManagerError};

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
    #[error("signing key state unavailable: {0}")]
    KeyState(#[from] KeyManagerError),
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
    let decoding_key = match keys.verification_key_for(key_id) {
        Ok(key) => key,
        Err(KeyManagerError::UnknownKeyId) => {
            return Err(TokenError::Validation(invalid_token_error()));
        }
        Err(error) => return Err(TokenError::KeyState(error)),
    };
    let data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(TokenError::Validation)?;
    Ok(data.claims)
}

fn invalid_token_error() -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
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
    let signing_key = keys.active_signing_key().map_err(TokenError::KeyState)?;
    header.kid = Some(signing_key.key_id().to_owned());
    encode(&header, &claims, signing_key.encoding_key()).map_err(TokenError::from)
}
