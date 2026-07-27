use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub value: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeError {
    #[error("authorization code has expired")]
    Expired,
    #[error("authorization code was already redeemed")]
    AlreadyRedeemed,
}

impl AuthorizationCode {
    pub fn new(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
    ) -> Self {
        Self::new_with_nonce(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            None,
        )
    }

    pub fn new_with_nonce(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
    ) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            value: format!("cx-code-{}", Uuid::new_v4().simple()),
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            created_at,
            expires_at: created_at + Duration::minutes(5),
            redeemed_at: None,
        }
    }

    pub fn redeem_at(&mut self, now: OffsetDateTime) -> Result<(), CodeError> {
        if self.redeemed_at.is_some() {
            return Err(CodeError::AlreadyRedeemed);
        }
        if now >= self.expires_at {
            return Err(CodeError::Expired);
        }
        self.redeemed_at = Some(now);
        Ok(())
    }
}
