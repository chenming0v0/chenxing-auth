use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub csrf_token: String,
    pub revoked_at: Option<OffsetDateTime>,
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
        let mut csrf_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        Ok(Self {
            id: Uuid::new_v4(),
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
