use super::*;

fn assert_userinfo_is_rejected(name: &'static str, credential_urls: [(&str, &str); 2]) {
    for (value, credential) in credential_urls {
        let parsed = url::Url::parse(value).expect("userinfo fixture must be a valid URL");
        assert!(!parsed.username().is_empty() || parsed.password().is_some());

        let error = parse_root_http_url(value, name)
            .expect_err("URL userinfo must be rejected during configuration validation");

        assert_eq!(error, ConfigError::InvalidValue(name));
        let message = error.to_string();
        assert_eq!(message, format!("invalid configuration value: {name}"));
        assert!(!message.contains(credential));
    }
}

#[test]
fn app_issuer_rejects_url_userinfo_without_echoing_credentials() {
    assert_userinfo_is_rejected(
        "APP_ISSUER",
        [
            ("https://issuer-user@auth.example.com", "issuer-user"),
            ("https://:issuer-password@auth.example.com", "issuer-password"),
        ],
    );

    assert!(parse_root_http_url("https://auth.example.com", "APP_ISSUER").is_ok());
}

#[test]
fn webauthn_origin_rejects_url_userinfo_without_echoing_credentials() {
    assert_userinfo_is_rejected(
        "WEBAUTHN_ORIGIN",
        [
            ("https://origin-user@auth.example.com", "origin-user"),
            ("https://:origin-password@auth.example.com", "origin-password"),
        ],
    );

    assert!(parse_root_http_url("http://localhost:5175", "WEBAUTHN_ORIGIN").is_ok());
}
