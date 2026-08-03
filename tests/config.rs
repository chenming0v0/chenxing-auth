use chenxing_auth::clients::domain::{
    DEFAULT_MAX_REDIRECT_URI_LENGTH, DEFAULT_MAX_REDIRECT_URIS, DEFAULT_MAX_SCOPE_LENGTH,
    DEFAULT_MAX_SCOPES,
};
use chenxing_auth::config::{AuthEncryptionKey, AuthEncryptionKeyRing, Config, ConfigError};

#[test]
fn config_accepts_valid_runtime_values() {
    let config = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect("valid configuration");

    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 3000);
    assert_eq!(config.session_ttl_seconds, 3600);
    assert!(!config.session_token_response_enabled);
    assert_eq!(config.key_rotation_grace_seconds, 604800);
    assert_eq!(
        config.client_registration_limits.max_redirect_uris,
        DEFAULT_MAX_REDIRECT_URIS
    );
    assert_eq!(
        config.client_registration_limits.max_redirect_uri_length,
        DEFAULT_MAX_REDIRECT_URI_LENGTH
    );
    assert_eq!(
        config.client_registration_limits.max_scopes,
        DEFAULT_MAX_SCOPES
    );
    assert_eq!(
        config.client_registration_limits.max_scope_length,
        DEFAULT_MAX_SCOPE_LENGTH
    );
}

#[test]
fn config_rejects_empty_database_url() {
    let error = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        String::new(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect_err("empty database URL must be rejected");

    assert!(matches!(error, ConfigError::MissingValue("DATABASE_URL")));
}

#[test]
fn config_rejects_zero_session_ttl() {
    let error = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        0,
    )
    .expect_err("zero TTL must be rejected");

    assert!(matches!(
        error,
        ConfigError::InvalidValue("SESSION_TTL_SECONDS")
    ));
}

#[test]
fn config_debug_does_not_expose_authentication_key() {
    let key = AuthEncryptionKey::new([7_u8; 32]);
    let debug = format!("{key:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("7"));
}

#[test]
fn encryption_key_ring_selects_active_key_and_keeps_old_keys_readable() {
    let ring = AuthEncryptionKeyRing::from_entries(
        "current".to_owned(),
        vec![
            ("current".to_owned(), AuthEncryptionKey::new([1_u8; 32])),
            ("previous".to_owned(), AuthEncryptionKey::new([2_u8; 32])),
        ],
    )
    .expect("valid key ring");

    assert_eq!(ring.active_kid(), "current");
    assert_eq!(ring.active_key().as_bytes(), &[1_u8; 32]);
    assert!(ring.key("previous").is_some());
}

#[test]
fn encryption_key_ring_rejects_duplicate_key_ids() {
    let error = AuthEncryptionKeyRing::from_entries(
        "current".to_owned(),
        vec![
            ("current".to_owned(), AuthEncryptionKey::new([1_u8; 32])),
            ("current".to_owned(), AuthEncryptionKey::new([2_u8; 32])),
        ],
    )
    .expect_err("duplicate key ids must be rejected");

    assert_eq!(error, ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
}

#[test]
fn test_configuration_uses_a_webauthn_compatible_local_origin() {
    let config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect("valid configuration");

    assert_eq!(config.webauthn_rp_id, "localhost");
    assert_eq!(config.webauthn_origin, "http://localhost:3000");
}
