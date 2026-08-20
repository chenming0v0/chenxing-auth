use serde::{Deserialize, Serialize};

use super::domain::SettingsValidationError;

pub const DEFAULT_SESSION_TTL_SECONDS: u64 = crate::config::DEFAULT_BROWSER_SESSION_TTL_SECONDS;

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
    /// 未写入管理设置时的部署默认值。
    ///
    /// 绝对寿命必须来自 `SESSION_TTL_SECONDS`：缺行若回落到
    /// [`DEFAULT_SESSION_TTL_SECONDS`]（14 天），运维把环境变量收成 1 小时也
    /// 签不出对应窗口的会话（#645）。空闲超时一并带上启动配置，只作为缺行
    /// 默认；查找路径仍用 store 的启动期 idle 策略（#644）。
    pub fn from_boot_config(session_ttl_seconds: u64, session_idle_timeout_seconds: u64) -> Self {
        Self {
            session_ttl_seconds,
            session_idle_timeout_seconds,
        }
    }

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

#[cfg(test)]
#[path = "session_lifetime_tests.rs"]
mod tests;
