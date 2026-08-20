//! #645：缺行必须使用启动配置的绝对寿命，不能静默变成 14 天。

use super::*;
use crate::settings::{
    domain::SettingsValidationError,
    persisted::{PersistedLoadError, SettingDiagnostic, decode_persisted},
};

const FOURTEEN_DAYS: u64 = 14 * 24 * 60 * 60;
const ONE_HOUR: u64 = 3_600;
const THIRTY_MINUTES: u64 = 1_800;

fn boot_default() -> SessionLifetimeSetting {
    SessionLifetimeSetting::from_boot_config(ONE_HOUR, THIRTY_MINUTES)
}

fn require(raw: Option<&str>) -> Result<SessionLifetimeSetting, PersistedLoadError> {
    decode_persisted(raw).require(
        boot_default(),
        |value| value,
        SessionLifetimeSetting::validate,
    )
}

fn inspect(
    raw: Option<&str>,
) -> crate::settings::persisted::SettingInspection<SessionLifetimeSetting> {
    decode_persisted(raw).inspect(
        boot_default(),
        |value| value,
        SessionLifetimeSetting::validate,
    )
}

#[test]
fn boot_config_ttl_is_not_replaced_by_the_fourteen_day_constant() {
    let setting = boot_default();
    assert_eq!(setting.session_ttl_seconds, ONE_HOUR);
    assert_ne!(setting.session_ttl_seconds, DEFAULT_SESSION_TTL_SECONDS);
    assert_eq!(setting.session_idle_timeout_seconds, THIRTY_MINUTES);
}

#[test]
fn default_remains_the_documented_fourteen_day_overlay() {
    assert_eq!(DEFAULT_SESSION_TTL_SECONDS, FOURTEEN_DAYS);
    assert_eq!(
        SessionLifetimeSetting::default().session_ttl_seconds,
        FOURTEEN_DAYS
    );
}

/// 失败场景：SESSION_TTL_SECONDS=3600 且没有持久化行时，签发寿命必须是 1 小时。
#[test]
fn missing_row_honors_boot_config_instead_of_fourteen_days() {
    let setting = require(None).expect("missing row is a legal initial state");
    assert_eq!(setting.session_ttl_seconds, ONE_HOUR);
    assert_ne!(setting.session_ttl_seconds, FOURTEEN_DAYS);
    assert!(inspect(None).diagnostic.is_none());
    assert_eq!(inspect(None).value.session_ttl_seconds, ONE_HOUR);

    let created_at = time::OffsetDateTime::UNIX_EPOCH;
    let session = crate::sessions::domain::Session::new_at_with_idle_timeout(
        "7".to_owned(),
        std::time::Duration::from_secs(setting.session_ttl_seconds),
        std::time::Duration::from_secs(setting.session_idle_timeout_seconds),
        created_at,
    )
    .expect("session");
    assert_eq!(
        session.expires_at,
        created_at + time::Duration::seconds(ONE_HOUR as i64)
    );
    assert_ne!(
        session.expires_at,
        created_at + time::Duration::seconds(FOURTEEN_DAYS as i64)
    );
}

#[test]
fn persisted_admin_setting_overrides_boot_config() {
    let raw = r#"{"session_ttl_seconds":7200,"session_idle_timeout_seconds":1800}"#;
    let setting = require(Some(raw)).expect("valid persisted row");
    assert_eq!(setting.session_ttl_seconds, 7_200);
}

#[test]
fn out_of_range_persisted_ttl_fails_closed() {
    let raw = r#"{"session_ttl_seconds":0,"session_idle_timeout_seconds":1800}"#;
    let error = require(Some(raw)).expect_err("zero TTL must fail closed");
    assert!(matches!(
        error,
        PersistedLoadError::Invalid(SettingsValidationError::InvalidSessionLifetime)
    ));

    let inspection = inspect(Some(raw));
    assert_eq!(inspection.value.session_ttl_seconds, 0);
    assert!(matches!(
        inspection.diagnostic,
        Some(SettingDiagnostic::Invalid(
            SettingsValidationError::InvalidSessionLifetime
        ))
    ));
}

#[test]
fn corrupt_json_fails_closed_and_admin_sees_boot_config() {
    for raw in ["not json", "{", "[]", "null", "42"] {
        assert!(
            matches!(require(Some(raw)), Err(PersistedLoadError::Corrupt(_))),
            "{raw:?}"
        );
        let inspection = inspect(Some(raw));
        assert_eq!(inspection.diagnostic, Some(SettingDiagnostic::Corrupt));
        assert_eq!(inspection.value, boot_default());
        assert_ne!(inspection.value.session_ttl_seconds, FOURTEEN_DAYS);
    }
}

#[test]
fn local_and_external_login_share_the_session_lifetime_setting() {
    let login = include_str!("../auth_factors/session.rs");
    let callback = include_str!("../oauth/providers/handlers/callback.rs");
    assert!(login.contains("settings.session_lifetime()"));
    assert!(callback.contains("settings.session_lifetime()"));
    assert!(!login.contains("DEFAULT_SESSION_TTL_SECONDS"));
    assert!(!callback.contains("DEFAULT_SESSION_TTL_SECONDS"));
}
