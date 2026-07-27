use jsonwebtoken::{Algorithm, Header, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::KeyManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IdTokenProfile<'a> {
    pub nonce: Option<&'a str>,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum IdTokenError {
    #[error("ID token lifetime is invalid")]
    InvalidLifetime,
    #[error("ID token signing failed: {0}")]
    Signing(#[from] jsonwebtoken::errors::Error),
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
        nonce: profile.nonce.map(str::to_owned),
        email: profile.email.map(str::to_owned),
        name: profile.name.map(str::to_owned),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id().to_owned());
    encode(&header, &claims, keys.encoding_key()).map_err(IdTokenError::from)
}
