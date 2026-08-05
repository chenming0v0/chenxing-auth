use chenxing_auth::oauth::providers::domain::{
    ClientAuthMethod, ExternalUser, ProviderInput, ProviderValidationError, extract_claim,
};
use serde_json::json;

fn valid_input() -> ProviderInput {
    ProviderInput {
        name: "企业 SSO".to_owned(),
        slug: "enterprise-sso".to_owned(),
        authorization_endpoint: "https://sso.example.com/oauth/authorize".to_owned(),
        token_endpoint: "https://sso.example.com/oauth/token".to_owned(),
        userinfo_endpoint: "https://sso.example.com/oauth/userinfo".to_owned(),
        client_id: "client-id".to_owned(),
        client_secret: Some("client-secret".to_owned()),
        scopes: vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
        subject_claim: "sub".to_owned(),
        email_claim: "email".to_owned(),
        name_claim: Some("name".to_owned()),
        email_verified_claim: Some("email_verified".to_owned()),
        client_auth_method: ClientAuthMethod::Basic,
        pkce_enabled: true,
    }
}

#[test]
fn provider_input_accepts_standard_https_configuration() {
    let provider = valid_input().validate().expect("valid provider");

    assert_eq!(provider.slug, "enterprise-sso");
    assert_eq!(provider.client_auth_method, ClientAuthMethod::Basic);
    assert!(provider.pkce_enabled);
}

/// RFC 9700 §2.1.1：PKCE 是默认行为。请求体未提供 `pkce_enabled` 时必须为 true，
/// 否则存量管理脚本会静默地把外部登录降级成无 PKCE 的流程。
#[test]
fn provider_input_defaults_pkce_to_enabled() {
    let input: ProviderInput = serde_json::from_value(json!({
        "name": "企业 SSO",
        "slug": "enterprise-sso",
        "authorization_endpoint": "https://sso.example.com/oauth/authorize",
        "token_endpoint": "https://sso.example.com/oauth/token",
        "userinfo_endpoint": "https://sso.example.com/oauth/userinfo",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "scopes": ["openid"]
    }))
    .expect("provider input without pkce_enabled");
    assert!(input.pkce_enabled);
    assert!(input.validate().expect("valid provider").pkce_enabled);
}

/// 个别外部 IdP 不支持 RFC 7636，必须能显式关闭，而不是全局禁用 PKCE。
#[test]
fn provider_input_allows_explicitly_disabling_pkce() {
    let mut input = valid_input();
    input.pkce_enabled = false;
    assert!(!input.validate().expect("valid provider").pkce_enabled);
}

#[test]
fn provider_input_rejects_unsafe_slug_and_endpoint() {
    let mut input = valid_input();
    input.slug = "../admin".to_owned();
    assert_eq!(
        input.validate().expect_err("invalid slug"),
        ProviderValidationError::InvalidSlug
    );

    let mut input = valid_input();
    input.authorization_endpoint = "javascript:alert(1)".to_owned();
    assert_eq!(
        input.validate().expect_err("invalid endpoint"),
        ProviderValidationError::InvalidEndpoint
    );
}

#[test]
fn provider_input_rejects_remote_http_but_allows_loopback_http() {
    let mut input = valid_input();
    input.authorization_endpoint = "http://sso.example.com/oauth/authorize".to_owned();
    assert_eq!(
        input.validate().expect_err("remote HTTP endpoint"),
        ProviderValidationError::InvalidEndpoint
    );

    let mut input = valid_input();
    input.token_endpoint = "http://sso.example.com/oauth/token".to_owned();
    assert_eq!(
        input.validate().expect_err("remote HTTP endpoint"),
        ProviderValidationError::InvalidEndpoint
    );

    let mut input = valid_input();
    input.userinfo_endpoint = "http://sso.example.com/oauth/userinfo".to_owned();
    assert_eq!(
        input.validate().expect_err("remote HTTP endpoint"),
        ProviderValidationError::InvalidEndpoint
    );

    let mut input = valid_input();
    input.authorization_endpoint = "http://localhost.example.com/oauth/authorize".to_owned();
    assert_eq!(
        input.validate().expect_err("non-loopback localhost suffix"),
        ProviderValidationError::InvalidEndpoint
    );

    let mut input = valid_input();
    input.authorization_endpoint = "http://127.0.0.1:8080/oauth/authorize".to_owned();
    input.token_endpoint = "http://[::1]:8080/oauth/token".to_owned();
    input.userinfo_endpoint = "http://localhost:8080/oauth/userinfo".to_owned();
    input.validate().expect("loopback HTTP endpoints");
}

#[test]
fn claim_extraction_supports_nested_paths_without_coercing_objects() {
    let value = json!({"profile": {"email": "person@example.com", "name": "Person"}});

    assert_eq!(
        extract_claim(&value, "profile.email").and_then(|value| value.as_str()),
        Some("person@example.com")
    );
    assert!(extract_claim(&value, "profile").is_some());
    assert!(extract_claim(&value, "profile.missing").is_none());
}

#[test]
fn external_user_requires_valid_email_and_subject() {
    let user = ExternalUser::from_claims(
        &json!({
            "sub": "subject-1",
            "email": "person@example.com",
            "name": "Person",
            "email_verified": true
        }),
        &valid_input().validate().expect("provider"),
    )
    .expect("claims");

    assert_eq!(user.subject, "subject-1");
    assert_eq!(user.email, "person@example.com");
    assert!(user.email_verified);
}

#[test]
fn external_user_rejects_unverified_claim_when_configured() {
    let error = ExternalUser::from_claims(
        &json!({"sub": "subject-1", "email": "person@example.com", "email_verified": false}),
        &valid_input().validate().expect("provider"),
    )
    .expect_err("unverified email");

    assert_eq!(error, ProviderValidationError::EmailNotVerified);
}
