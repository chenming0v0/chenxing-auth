//! `app_settings.setting_value` JSON 的回读入口（#449）。
//!
//! 管理 API 继续用领域类型的严格 Deserialize：缺字段就是 400，不能和回读
//! 共用 `#[serde(default)]`。否则 PUT 漏字段会按默认值覆盖已经收紧的阈值，
//! 等于在写路径上静默放宽安全边界。
//!
//! 回读策略：
//! - Passkey / SecurityLimits：用 `Default` 补缺失键，已写入的键原样保留。
//!   补的是当前安全默认值，不是类型零值（`account_failure_limit` 缺了补 10，
//!   不是 0，更不是饱和值）。
//! - EmailPolicy：`whitelist_enabled` 缺失视为结构漂移，拒绝解析。缺这个键
//!   就按 Default 补会变成「放行一切」，旧实现已经因此出过缺口。
//!   `alias_restriction_enabled` / `allowed_domains` 可以缺，按 Default 补
//!   （false / 空列表）；白名单已开启且域名为空时 `allows_email` 仍拒绝。

use serde::Serialize;
use serde::de::{DeserializeOwned, Error as DeError};

use super::{EmailPolicySetting, PasskeySetting, SecurityLimitsSetting};

pub fn parse_passkey(raw: &str) -> Result<PasskeySetting, serde_json::Error> {
    overlay_defaults(raw, &PasskeySetting::default())
}

pub fn parse_email_policy(raw: &str) -> Result<EmailPolicySetting, serde_json::Error> {
    let stored: serde_json::Value = serde_json::from_str(raw)?;
    match &stored {
        serde_json::Value::Object(object) if object.contains_key("whitelist_enabled") => {
            overlay_value(stored, &EmailPolicySetting::default())
        }
        serde_json::Value::Object(_) => Err(DeError::custom(
            "stored email policy is missing whitelist_enabled",
        )),
        other => serde_json::from_value(other.clone()),
    }
}

pub fn parse_security_limits(raw: &str) -> Result<SecurityLimitsSetting, serde_json::Error> {
    overlay_defaults(raw, &SecurityLimitsSetting::default())
}

fn overlay_defaults<T>(raw: &str, defaults: &T) -> Result<T, serde_json::Error>
where
    T: Serialize + DeserializeOwned,
{
    let stored: serde_json::Value = serde_json::from_str(raw)?;
    overlay_value(stored, defaults)
}

fn overlay_value<T>(stored: serde_json::Value, defaults: &T) -> Result<T, serde_json::Error>
where
    T: Serialize + DeserializeOwned,
{
    match stored {
        serde_json::Value::Object(overlay) => {
            let mut merged = serde_json::to_value(defaults).map_err(DeError::custom)?;
            if let serde_json::Value::Object(base) = &mut merged {
                for (key, value) in overlay {
                    base.insert(key, value);
                }
            }
            serde_json::from_value(merged)
        }
        other => serde_json::from_value(other),
    }
}

#[cfg(test)]
#[path = "persisted_tests.rs"]
mod tests;
