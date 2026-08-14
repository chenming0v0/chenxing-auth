use super::*;

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("{raw:?} must parse: {error}"))
}

/// Issue #302：白名单存 IDNA 匹配形态，Unicode 与 Punycode 两种填写等价。
#[test]
fn whitelist_domains_are_canonicalized_to_the_matching_form() {
    let policy = EmailPolicySetting {
        whitelist_enabled: true,
        alias_restriction_enabled: false,
        allowed_domains: vec!["ÉXAMPLE.COM".to_owned(), "xn--xample-9ua.com".to_owned()],
    }
    .validate()
    .expect("unicode whitelist domain must be accepted");

    // 两种填写去重成同一个键。
    assert_eq!(
        policy.allowed_domains,
        vec!["xn--xample-9ua.com".to_owned()]
    );
    // 邮箱侧的任意等价书写都能命中它。
    for raw in [
        "user@éxample.com",
        "user@ÉXAMPLE.COM",
        "user@xn--xample-9ua.com",
    ] {
        assert!(policy.allows_email(&email(raw)), "{raw}");
    }
    assert!(!policy.allows_email(&email("user@other.example")));
}

#[test]
fn structurally_invalid_whitelist_domains_are_rejected() {
    for domain in [
        "example",
        ".example.com",
        "example.com.",
        "example..com",
        "user@example.com",
    ] {
        let error = EmailPolicySetting {
            whitelist_enabled: true,
            alias_restriction_enabled: false,
            allowed_domains: vec![domain.to_owned()],
        }
        .validate()
        .expect_err("invalid whitelist domain must be rejected");
        assert!(
            matches!(error, SettingsValidationError::InvalidEmailDomain),
            "{domain}"
        );
    }
}

#[test]
fn validates_passkey_and_email_policy() {
    let passkey = PasskeySetting {
        enabled: true,
        rp_name: "辰星认证中枢".to_owned(),
        rp_id: "auth.clya.top".to_owned(),
        user_verification: PasskeyUserVerification::Preferred,
        authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
        allow_insecure_origin: false,
        allowed_origins: vec!["https://auth.clya.top".to_owned()],
    }
    .validate()
    .expect("passkey");
    assert_eq!(
        passkey.allowed_origins,
        vec!["https://auth.clya.top".to_owned()]
    );

    let policy = EmailPolicySetting {
        whitelist_enabled: true,
        alias_restriction_enabled: true,
        allowed_domains: vec!["Gmail.COM".to_owned(), "gmail.com".to_owned()],
    }
    .validate()
    .expect("policy");
    assert_eq!(policy.allowed_domains, vec!["gmail.com".to_owned()]);
    assert!(policy.allows_email(&email("user@gmail.com")));
    assert!(!policy.allows_email(&email("user+tag@gmail.com")));
    assert!(!policy.allows_email(&email("user@tempmail.com")));
    // 大小写变体走同一个匹配域名，命中同一条白名单。
    assert!(policy.allows_email(&email("User@GMAIL.com")));
}

#[test]
fn canonicalizes_default_and_explicit_origin_ports() {
    let passkey = PasskeySetting {
        enabled: true,
        rp_name: "辰星认证中枢".to_owned(),
        rp_id: "example.com".to_owned(),
        user_verification: PasskeyUserVerification::Preferred,
        authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
        allow_insecure_origin: true,
        allowed_origins: vec![
            "https://login.example.com".to_owned(),
            "https://login.example.com:443".to_owned(),
            "http://login.example.com:80".to_owned(),
            "https://login.example.com:8443".to_owned(),
            "http://login.example.com:8080".to_owned(),
        ],
    }
    .validate()
    .expect("passkey");

    assert_eq!(
        passkey.allowed_origins,
        vec![
            "https://login.example.com".to_owned(),
            "http://login.example.com".to_owned(),
            "https://login.example.com:8443".to_owned(),
            "http://login.example.com:8080".to_owned(),
        ]
    );
}

fn validate_passkey_with_rp_id(rp_id: &str) -> Result<PasskeySetting, SettingsValidationError> {
    PasskeySetting {
        enabled: true,
        rp_name: "辰星认证中枢".to_owned(),
        rp_id: rp_id.to_owned(),
        user_verification: PasskeyUserVerification::Preferred,
        authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
        allow_insecure_origin: false,
        allowed_origins: vec![format!("https://{rp_id}")],
    }
    .validate()
}

/// Issue #452：公共后缀本身就是 PSL 条目，把它当 rp_id 会让所有子域共享同一条
/// 信任边界，浏览器端 WebAuthn 也拒绝这类值。必须拒绝。
#[test]
fn rp_id_rejects_public_suffixes() {
    for rp_id in ["co.uk", "com.cn", "github.io", "com", "uk", "ac.cn"] {
        assert!(
            !is_registrable_rp_id(rp_id),
            "public suffix {rp_id:?} must not be a registrable rp_id"
        );
        assert!(
            matches!(
                validate_passkey_with_rp_id(rp_id),
                Err(SettingsValidationError::InvalidPasskeyRpId)
            ),
            "validate must reject public suffix {rp_id:?}"
        );
    }
}

/// Issue #452：有效 eTLD+1、多级子域、Punycode IDN、localhost 与 IPv4 均接受。
#[test]
fn rp_id_accepts_registrable_domains_and_exceptions() {
    for rp_id in [
        "example.com",
        "example.co.uk",
        "user.github.io",
        "auth.clya.top",
        "xn--xample-9ua.com",
        "localhost",
        "127.0.0.1",
        "192.168.1.5",
    ] {
        assert!(
            is_registrable_rp_id(rp_id),
            "registrable rp_id {rp_id:?} must be accepted"
        );
        validate_passkey_with_rp_id(rp_id)
            .unwrap_or_else(|error| panic!("validate must accept {rp_id:?}: {error}"));
    }
}
