use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub value: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RefreshTokenError {
    #[error("refresh token is expired")]
    Expired,
    #[error("refresh token is revoked")]
    Revoked,
    #[error("refresh token is not bound to client")]
    ClientMismatch,
}

impl RefreshToken {
    pub fn new(client_id: String, user_id: String, scopes: Vec<String>) -> Self {
        Self::new_with_nonce(client_id, user_id, scopes, None)
    }

    pub fn new_with_nonce(
        client_id: String,
        user_id: String,
        scopes: Vec<String>,
        nonce: Option<String>,
    ) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            value: format!("cx-refresh-{}", Uuid::new_v4().simple()),
            client_id,
            user_id,
            scopes,
            nonce,
            created_at,
            expires_at: created_at + Duration::days(30),
            revoked_at: None,
        }
    }

    pub fn validate(&self, client_id: &str, now: OffsetDateTime) -> Result<(), RefreshTokenError> {
        if self.client_id != client_id {
            return Err(RefreshTokenError::ClientMismatch);
        }
        if self.revoked_at.is_some() {
            return Err(RefreshTokenError::Revoked);
        }
        if now >= self.expires_at {
            return Err(RefreshTokenError::Expired);
        }
        Ok(())
    }

    pub fn is_valid_for(&self, client_id: &str, now: OffsetDateTime) -> bool {
        self.validate(client_id, now).is_ok()
    }
}
