use chenxing_auth::config::{Config, ConfigError};

#[test]
fn config_preserves_explicit_issuer_url() {
    let config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://localhost:3000".to_owned(),
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect("valid issuer configuration");

    assert_eq!(
        config.issuer.as_ref().map(|i| i.as_str()),
        Some("http://localhost:3000")
    );
}

#[test]
fn config_rejects_issuer_with_path() {
    let error = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "https://auth.example.com/path".to_owned(),
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect_err("issuer path must be rejected");

    assert!(matches!(error, ConfigError::InvalidValue("APP_ISSUER")));
}
