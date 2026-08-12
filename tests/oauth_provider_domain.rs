use chenxing_auth::oauth::providers::{
    claims::{ClaimMapping, ExternalUser, extract_claim},
    domain::{ClientAuthMethod, ProviderInput, ProviderValidationError},
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
        "scopes": ["openid"],
        "email_verified_claim": "email_verified"
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

fn mapping() -> ClaimMapping {
    valid_input().validate().expect("provider").claims
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
        &mapping(),
    )
    .expect("claims");

    assert_eq!(user.subject, "subject-1");
    assert_eq!(user.email.display(), "person@example.com");
    assert_eq!(user.email.canonical(), "person@example.com");
    assert!(user.email_verified);
}

/// Issue #302：外部 IdP 的邮箱走同一个规范化入口。
///
/// IdP 返回的书写形态不可控。若这里不规范化，同一个邮箱在 IdP 换一种大小写或
/// Unicode 形态返回时会绕过"邮箱已注册"判定，建出第二个账号。
#[test]
fn external_user_canonicalizes_the_provider_email() {
    let user = ExternalUser::from_claims(
        &json!({
            "sub": "subject-1",
            "email": "Person@ÉXAMPLE.COM",
            "email_verified": true
        }),
        &mapping(),
    )
    .expect("claims");

    assert_eq!(user.email.display(), "Person@xn--xample-9ua.com");
    assert_eq!(user.email.canonical(), "person@xn--xample-9ua.com");
}

/// 无法规范化的邮箱 claim 被拒绝，不建号。
#[test]
fn external_user_rejects_uncanonicalizable_email() {
    for value in ["person@localhost", "person", "person@", "@example.com"] {
        let error = ExternalUser::from_claims(
            &json!({"sub": "subject-1", "email": value, "email_verified": true}),
            &mapping(),
        )
        .expect_err("uncanonicalizable email must be rejected");
        assert_eq!(error, ProviderValidationError::InvalidEmail, "{value}");
    }
}

#[test]
fn external_user_rejects_unverified_claim_when_configured() {
    let error = ExternalUser::from_claims(
        &json!({"sub": "subject-1", "email": "person@example.com", "email_verified": false}),
        &mapping(),
    )
    .expect_err("unverified email");

    assert_eq!(error, ProviderValidationError::EmailNotVerified);
}

/// Issue #261 的核心回归：claim 缺失过去会被当成「未配置」而放行建号。
/// 现在 claim 路径恒存在，缺失的是 IdP 响应，必须 fail-closed。
#[test]
fn external_user_rejects_missing_email_verified_claim_in_response() {
    let error = ExternalUser::from_claims(
        &json!({"sub": "subject-1", "email": "person@example.com", "name": "Person"}),
        &mapping(),
    )
    .expect_err("missing email_verified claim");

    assert_eq!(error, ProviderValidationError::EmailNotVerified);
}

/// 非 bool 一律拒绝：字符串 "true"、数字 1、null 都不构成验证证据。
/// 放宽任何一种都等价于接受 IdP 的自由文本作为安全断言。
#[test]
fn external_user_rejects_non_boolean_email_verified_claim() {
    for value in [
        json!("true"),
        json!(1),
        json!(null),
        json!({}),
        json!([true]),
    ] {
        let error = ExternalUser::from_claims(
            &json!({"sub": "subject-1", "email": "person@example.com", "email_verified": value}),
            &mapping(),
        )
        .expect_err("non-boolean email_verified claim");

        assert_eq!(error, ProviderValidationError::EmailNotVerified);
    }
}

/// provider 配置必须带 email_verified_claim，否则连保存都不允许。
#[test]
fn provider_input_rejects_missing_or_blank_email_verified_claim() {
    for claim in [None, Some(String::new()), Some("   ".to_owned())] {
        let mut input = valid_input();
        input.email_verified_claim = claim;
        assert_eq!(
            input.validate().expect_err("missing email_verified_claim"),
            ProviderValidationError::MissingEmailVerifiedClaim
        );
    }
}

/// 省略该字段的旧请求体同样被拒，而不是静默降级成「不校验邮箱」。
#[test]
fn provider_input_without_email_verified_claim_field_is_rejected() {
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
    .expect("provider input without email_verified_claim");

    assert_eq!(
        input.validate().expect_err("missing email_verified_claim"),
        ProviderValidationError::MissingEmailVerifiedClaim
    );
}

/// 嵌套路径要能用：不少 IdP 把验证状态放在 profile 子对象里。
#[test]
fn email_verified_claim_supports_nested_path() {
    let mut input = valid_input();
    input.email_verified_claim = Some("profile.email_verified".to_owned());
    let mapping = input.validate().expect("provider").claims;

    ExternalUser::from_claims(
        &json!({
            "sub": "subject-1",
            "email": "person@example.com",
            "profile": {"email_verified": true}
        }),
        &mapping,
    )
    .expect("nested verified claim");

    let error = ExternalUser::from_claims(
        &json!({
            "sub": "subject-1",
            "email": "person@example.com",
            "profile": {"email_verified": false}
        }),
        &mapping,
    )
    .expect_err("nested unverified claim");
    assert_eq!(error, ProviderValidationError::EmailNotVerified);
}

/// ClaimMapping 构造即校验，非法路径不会进入解析阶段。
#[test]
fn claim_mapping_rejects_invalid_paths() {
    assert_eq!(
        ClaimMapping::new(
            "sub".to_owned(),
            "email".to_owned(),
            None,
            Some("email verified".to_owned()),
        )
        .expect_err("invalid claim path"),
        ProviderValidationError::InvalidClaimPath
    );
    assert_eq!(
        ClaimMapping::new("sub".to_owned(), "email".to_owned(), None, None)
            .expect_err("missing email_verified"),
        ProviderValidationError::MissingEmailVerifiedClaim
    );
}
