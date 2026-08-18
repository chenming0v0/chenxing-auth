use serde::{Deserialize, Serialize};

use super::domain::SettingsValidationError;

pub const DEFAULT_SESSION_TTL_SECONDS: u64 = 14 * 24 * 60 * 60;

/// 浏览器会话生命周期。修改只影响之后签发的会话；已签发会话保留创建时的截止时间。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLifetimeSetting {
    pub session_ttl_seconds: u64,
    pub session_idle_timeout_seconds: u64,
}

impl Default for SessionLifetimeSetting {
    fn default() -> Self {
        Self {
            session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
            session_idle_timeout_seconds: DEFAULT_SESSION_TTL_SECONDS,
        }
    }
}

impl SessionLifetimeSetting {
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        if !(1..=crate::config::MAX_SESSION_TTL_SECONDS).contains(&self.session_ttl_seconds)
            || !(1..=crate::config::MAX_SESSION_IDLE_TIMEOUT_SECONDS)
                .contains(&self.session_idle_timeout_seconds)
        {
            return Err(SettingsValidationError::InvalidSessionLifetime);
        }
        Ok(self)
    }
}
