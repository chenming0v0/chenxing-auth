use chenxing_auth::config::{Config, ConfigError};

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
