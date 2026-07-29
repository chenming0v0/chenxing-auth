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
    }
}

#[test]
fn provider_input_accepts_standard_https_configuration() {
    let provider = valid_input().validate().expect("valid provider");

    assert_eq!(provider.slug, "enterprise-sso");
    assert_eq!(provider.client_auth_method, ClientAuthMethod::Basic);
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
