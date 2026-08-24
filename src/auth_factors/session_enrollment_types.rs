use super::domain::FactorMethod;
use crate::users::domain::UserId;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PendingSessionEnrollment<P> {
    pub(super) binding: PendingSessionBinding,
    pub(super) method: FactorMethod,
    pub(super) enrollment_id: String,
    pub(super) expires_at: OffsetDateTime,
    pub(super) payload: P,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PendingSessionBinding {
    user_id: String,
    session_id: String,
    session_epoch: String,
}

impl PendingSessionBinding {
    pub(super) fn new(user_id: UserId, session_id: i64, session_epoch: i64) -> Self {
        Self {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            session_epoch: session_epoch.to_string(),
        }
    }
}

impl<P> fmt::Debug for PendingSessionEnrollment<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSessionEnrollment")
            .field("binding", &self.binding)
            .field("method", &self.method)
            .field("enrollment_id", &self.enrollment_id)
            .field("expires_at", &self.expires_at)
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PendingTotpPayload {
    pub(super) encrypted_secret: Vec<u8>,
}

impl<P> PendingSessionEnrollment<P> {
    pub(super) fn matches(
        &self,
        user_id: UserId,
        session_id: i64,
        session_epoch: i64,
        method: FactorMethod,
        enrollment_id: &str,
    ) -> bool {
        self.binding.user_id == user_id.to_string()
            && self.binding.session_id == session_id.to_string()
            && self.binding.session_epoch == session_epoch.to_string()
            && self.method == method
            && self.enrollment_id == enrollment_id
    }
}
