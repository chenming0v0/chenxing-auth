use super::*;
use crate::config::TrustedProxies;

fn test_config() -> Config {
    Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://db-user:database-password@db.example/chenxing_auth".to_owned(),
        "redis://redis-user:redis-password@redis.example/0".to_owned(),
        3600,
    )
    .expect("valid test configuration")
}

fn production_like_config() -> Config {
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "https://auth.example.com".to_owned(),
        "postgres://db-user:database-password@db.example/chenxing_auth".to_owned(),
        "redis://redis-user:redis-password@redis.example/0".to_owned(),
        3600,
    )
    .expect("valid production-like configuration");
    config.admin_token = "local-development-admin-token-012345".to_owned();
    config.trusted_proxies = TrustedProxies::from_ips(vec![
        "127.0.0.1".parse().expect("loopback is a valid proxy IP"),
    ]);
    config
}

#[test]
fn test_constructor_collects_the_default_insecure_postures() {
    let warnings = test_config().startup_warnings();
    assert_eq!(
        warnings,
        [
            ConfigWarning::HttpIssuerSecureCookie,
            ConfigWarning::EmptyAdminToken,
            ConfigWarning::NoTrustedProxies,
        ]
    );
}

#[test]
fn empty_admin_token_is_its_own_warning() {
    let mut config = production_like_config();
    config.admin_token.clear();
    assert_eq!(config.startup_warnings(), [ConfigWarning::EmptyAdminToken]);
}

#[test]
fn oauth_loopback_exception_is_its_own_warning() {
    let mut config = production_like_config();
    config.oauth_provider_loopback_enabled = true;
    assert_eq!(
        config.startup_warnings(),
        [ConfigWarning::OauthProviderLoopbackEnabled]
    );
}

#[test]
fn missing_trusted_proxies_is_its_own_warning() {
    let mut config = production_like_config();
    config.trusted_proxies = TrustedProxies::none();
    assert_eq!(config.startup_warnings(), [ConfigWarning::NoTrustedProxies]);
}

#[test]
fn http_issuer_with_secure_cookies_is_its_own_warning() {
    let mut config = production_like_config();
    config.issuer = Some(
        crate::config::IssuerUrl::parse("http://127.0.0.1:3000").expect("loopback HTTP issuer"),
    );
    assert_eq!(
        config.startup_warnings(),
        [ConfigWarning::HttpIssuerSecureCookie]
    );
}

#[test]
fn legacy_http_app_issuer_warns_even_when_runtime_issuer_is_unset() {
    let mut config = production_like_config();
    config.issuer = None;
    config.legacy_issuer_import = Some("http://127.0.0.1:3000".to_owned());
    assert_eq!(
        config.startup_warnings(),
        [ConfigWarning::HttpIssuerSecureCookie]
    );
}

#[test]
fn production_like_config_has_no_startup_warnings() {
    assert_eq!(production_like_config().startup_warnings(), []);
}

#[test]
fn invalid_log_filter_is_diagnosable_without_leaking_config() {
    let error = parse_log_filter("chenxing_auth=not-a-level")
        .expect_err("malformed RUST_LOG must fail closed");
    assert_eq!(error, ConfigError::InvalidValue("RUST_LOG"));

    let rendered = error.to_string();
    assert_eq!(rendered, "invalid configuration value: RUST_LOG");
    for secret in [
        "database-password",
        "redis-password",
        "local-development-admin-token-012345",
        "AUTH_ENCRYPTION_KEY",
    ] {
        assert!(
            !rendered.contains(secret),
            "log-filter error leaked {secret:?}: {rendered}"
        );
    }
}

#[test]
fn warning_messages_do_not_embed_credential_values() {
    let config = production_like_config();
    for warning in config.startup_warnings() {
        let message = warning.message();
        assert!(!message.contains("database-password"));
        assert!(!message.contains("redis-password"));
        assert!(!message.contains(&config.admin_token));
        assert!(!message.contains("postgres://"));
        assert!(!message.contains("redis://"));
    }
}
