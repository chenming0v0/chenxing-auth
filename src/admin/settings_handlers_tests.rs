use axum::{body::to_bytes, http::StatusCode};

use super::{SETTING_DIAGNOSTIC_HEADER, respond_setting_inspection};
use crate::settings::{SettingDiagnostic, SettingInspection, domain::SettingsValidationError};

fn diagnostic_header(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get(&SETTING_DIAGNOSTIC_HEADER)
        .map(|value| {
            value
                .to_str()
                .expect("diagnostic header must be visible ascii")
                .to_owned()
        })
}

#[tokio::test]
async fn valid_setting_response_omits_the_diagnostic_header() {
    let response = respond_setting_inspection(
        "passkey",
        SettingInspection {
            value: serde_json::json!({"enabled": true}),
            diagnostic: None,
        },
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(diagnostic_header(&response), None);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), br#"{"enabled":true}"#);
}

#[tokio::test]
async fn invalid_setting_response_exposes_only_the_stable_token() {
    let response = respond_setting_inspection(
        "passkey",
        SettingInspection {
            value: serde_json::json!({"rp_id": "com"}),
            diagnostic: Some(SettingDiagnostic::Invalid(
                SettingsValidationError::InvalidPasskeyRpId,
            )),
        },
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(diagnostic_header(&response).as_deref(), Some("invalid"));
    let rendered = format!("{response:?}");
    assert!(
        !rendered.contains("passkey relying party id is invalid"),
        "header must not carry the validation detail: {rendered}"
    );
}

#[tokio::test]
async fn corrupt_setting_response_does_not_echo_stored_payload() {
    let response = respond_setting_inspection(
        "email_policy",
        SettingInspection {
            value: serde_json::json!({"whitelist_enabled": false}),
            diagnostic: Some(SettingDiagnostic::Corrupt),
        },
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(diagnostic_header(&response).as_deref(), Some("corrupt"));
    let header = diagnostic_header(&response).expect("header");
    assert_eq!(header, "corrupt");
    assert!(!header.contains("SECRET"));
}
