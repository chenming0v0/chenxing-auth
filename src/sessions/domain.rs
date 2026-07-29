use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

    pub fn validates_csrf(&self, token: &str) -> bool {
        !token.is_empty() && self.csrf_token == token
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
}
