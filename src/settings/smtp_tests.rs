use super::*;

fn update(action: Option<SmtpPasswordAction>, password: Option<&str>) -> SmtpSettingUpdate {
    SmtpSettingUpdate {
        host: "smtp.example.com".to_owned(),
        port: 587,
        username: "noreply@example.com".to_owned(),
        from_address: "noreply@example.com".to_owned(),
        ssl_enabled: true,
        force_auth_login: false,
        password_action: action,
        password: password.map(str::to_owned),
    }
}

fn resolved(
    action: Option<SmtpPasswordAction>,
    password: Option<&str>,
) -> Result<SmtpPasswordUpdate, SettingsValidationError> {
    update(action, password)
        .validate()
        .map(|(_, password)| password)
}

#[test]
fn omitted_action_and_password_keeps_existing_secret() {
    assert_eq!(resolved(None, None), Ok(SmtpPasswordUpdate::Keep));
}

#[test]
fn omitted_action_with_nonempty_password_sets() {
    assert_eq!(
        resolved(None, Some("super-secret-smtp")),
        Ok(SmtpPasswordUpdate::Set("super-secret-smtp".to_owned()))
    );
}

#[test]
fn empty_password_is_never_silent_keep() {
    assert_eq!(
        resolved(None, Some("")),
        Err(SettingsValidationError::SmtpPasswordConflict)
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Keep), Some("")),
        Err(SettingsValidationError::SmtpPasswordConflict)
    );
}

#[test]
fn explicit_keep_rejects_any_password_value() {
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Keep), None),
        Ok(SmtpPasswordUpdate::Keep)
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Keep), Some("still-secret")),
        Err(SettingsValidationError::SmtpPasswordConflict)
    );
}

#[test]
fn explicit_set_requires_a_usable_password() {
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Set), Some("new-secret")),
        Ok(SmtpPasswordUpdate::Set("new-secret".to_owned()))
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Set), None),
        Err(SettingsValidationError::SmtpPasswordRequired)
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Set), Some("")),
        Err(SettingsValidationError::InvalidSmtpPassword)
    );
    assert_eq!(
        resolved(
            Some(SmtpPasswordAction::Set),
            Some(&"x".repeat(MAX_SMTP_PASSWORD_LENGTH + 1))
        ),
        Err(SettingsValidationError::InvalidSmtpPassword)
    );
}

#[test]
fn explicit_clear_rejects_a_password_value() {
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Clear), None),
        Ok(SmtpPasswordUpdate::Clear)
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Clear), Some("leftover")),
        Err(SettingsValidationError::SmtpPasswordConflict)
    );
    assert_eq!(
        resolved(Some(SmtpPasswordAction::Clear), Some("")),
        Err(SettingsValidationError::SmtpPasswordConflict)
    );
}

#[test]
fn next_ciphertext_keeps_sets_and_clears() {
    let existing = Some("cipher-old".to_owned());
    assert_eq!(
        SmtpPasswordUpdate::Keep
            .next_ciphertext(existing.clone(), |_| -> Result<String, ()> {
                panic!("keep")
            })
            .expect("keep"),
        existing
    );
    assert_eq!(
        SmtpPasswordUpdate::Set("plain".to_owned())
            .next_ciphertext(existing.clone(), |plain| Ok(format!("enc:{plain}")))
            .expect("set"),
        Some("enc:plain".to_owned())
    );
    assert_eq!(
        SmtpPasswordUpdate::Clear
            .next_ciphertext(existing, |_| -> Result<String, ()> { panic!("clear") })
            .expect("clear"),
        None
    );
    assert_eq!(
        SmtpPasswordUpdate::Keep
            .next_ciphertext(None, |_| -> Result<String, ()> { panic!("unconfigured") })
            .expect("unconfigured keep"),
        None
    );
}

#[test]
fn debug_and_json_never_echo_password_or_ciphertext() {
    let update = update(Some(SmtpPasswordAction::Set), Some("super-secret-smtp"));
    let rendered = format!("{update:?}");
    assert!(rendered.contains("password_action"));
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-smtp"));

    let set = SmtpPasswordUpdate::Set("super-secret-smtp".to_owned());
    assert_eq!(format!("{set:?}"), "Set(<redacted>)");
    assert!(!format!("{set:?}").contains("super-secret-smtp"));

    let stored = StoredSmtpSetting {
        host: "smtp.example.com".to_owned(),
        port: 587,
        username: "noreply@example.com".to_owned(),
        from_address: "noreply@example.com".to_owned(),
        ssl_enabled: true,
        force_auth_login: false,
        password_ciphertext: Some("cipher-blob".to_owned()),
    };
    let stored_debug = format!("{stored:?}");
    assert!(stored_debug.contains("<redacted>"));
    assert!(!stored_debug.contains("cipher-blob"));

    let public = SmtpSetting {
        password_configured: true,
        ..SmtpSetting::default()
    };
    let body = serde_json::to_value(&public).expect("smtp setting serializes");
    assert_eq!(body["password_configured"], true);
    assert!(body.get("password").is_none());
    assert!(body.get("password_ciphertext").is_none());
    assert!(body.get("password_action").is_none());
}

#[test]
fn password_action_deserializes_snake_case_and_rejects_unknown() {
    let keep: SmtpPasswordAction = serde_json::from_str("\"keep\"").expect("keep");
    let set: SmtpPasswordAction = serde_json::from_str("\"set\"").expect("set");
    let clear: SmtpPasswordAction = serde_json::from_str("\"clear\"").expect("clear");
    assert_eq!(keep, SmtpPasswordAction::Keep);
    assert_eq!(set, SmtpPasswordAction::Set);
    assert_eq!(clear, SmtpPasswordAction::Clear);
    assert!(serde_json::from_str::<SmtpPasswordAction>("\"delete\"").is_err());
}
