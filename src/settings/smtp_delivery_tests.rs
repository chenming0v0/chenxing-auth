use super::*;

fn stored() -> StoredSmtpSetting {
    StoredSmtpSetting {
        host: "smtp.example.com".to_owned(),
        port: 587,
        username: String::new(),
        from_address: "sender@example.com".to_owned(),
        ssl_enabled: true,
        force_auth_login: false,
        password_ciphertext: None,
    }
}

#[tokio::test]
async fn smtp_delivery_loads_no_auth_relay_without_requiring_a_secret() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let config = settings
        .decode_smtp_delivery_config(stored())
        .expect("no-auth relay configuration");
    assert!(config.username.is_empty());
    assert!(config.password.is_empty());
}

#[tokio::test]
async fn smtp_delivery_rejects_partial_authentication_and_unconfigured_senders() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let mut username_only = stored();
    username_only.username = "sender@example.com".to_owned();
    let mut login_without_credentials = stored();
    login_without_credentials.force_auth_login = true;
    let mut missing_host = stored();
    missing_host.host.clear();
    let mut missing_sender = stored();
    missing_sender.from_address.clear();
    for value in [
        username_only,
        login_without_credentials,
        missing_host,
        missing_sender,
    ] {
        assert!(matches!(
            settings.decode_smtp_delivery_config(value),
            Err(SettingsServiceError::Corrupt { .. })
        ));
    }
}

#[tokio::test]
async fn smtp_delivery_keeps_encrypted_credentials_and_rejects_password_only() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let mut authenticated = stored();
    authenticated.username = "sender@example.com".to_owned();
    authenticated.password_ciphertext = Some(SecretManager::encode(
        &settings
            .secrets
            .encrypt_for(SecretContext::Smtp, "fixture-password")
            .expect("encrypt fixture password"),
    ));
    let config = settings
        .decode_smtp_delivery_config(authenticated.clone())
        .expect("authenticated SMTP configuration");
    assert_eq!(config.password, "fixture-password");
    assert_eq!(config.username, "sender@example.com");
    authenticated.username.clear();
    assert!(matches!(
        settings.decode_smtp_delivery_config(authenticated),
        Err(SettingsServiceError::Corrupt { .. })
    ));
}
