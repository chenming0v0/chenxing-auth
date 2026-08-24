//! Issue #287：WebAuthn rp_id 必须是可注册域。
//!
//! origin 白名单按 `host == rp_id || host.ends_with(".{rp_id}")` 判定。单标签 rp_id
//! 会让这条后缀规则退化成通配，因此 rp_id 必须至少含一个点号；`localhost` 是唯一
//! 保留的开发例外（RFC 6761 保证它指向回环，不可能被他人注册）。
//!
//! 这些用例只走 `PasskeySetting::validate`，不连数据库。

use chenxing_auth::settings::{
    PasskeyAuthenticatorAttachment, PasskeySetting, PasskeyUserVerification,
    domain::SettingsValidationError,
};

fn setting(rp_id: &str, origins: &[&str]) -> PasskeySetting {
    PasskeySetting {
        enabled: true,
        rp_name: "辰星认证中枢".to_owned(),
        rp_id: rp_id.to_owned(),
        user_verification: PasskeyUserVerification::Preferred,
        authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
        allow_insecure_origin: false,
        allowed_origins: origins.iter().map(|origin| (*origin).to_owned()).collect(),
    }
}

/// 核心回归：`rp_id = "com"` 过去能通过校验，之后任意 `*.com` 都进得了白名单。
#[test]
fn single_label_rp_id_is_rejected() {
    for rp_id in ["com", "example", "corp", "internal", "LOCAL"] {
        let origin = format!("https://any.{}", rp_id.to_ascii_lowercase());
        let error = setting(rp_id, &[origin.as_str()])
            .validate()
            .expect_err("single-label rp_id");
        assert_eq!(
            error,
            SettingsValidationError::InvalidPasskeyRpId,
            "rp_id={rp_id} 必须按非可注册域拒绝"
        );
    }
}

/// 单标签 rp_id 不再能把任意公共后缀下的域名洗成合法 origin。
#[test]
fn single_label_rp_id_cannot_whitelist_arbitrary_origins() {
    assert!(
        setting("com", &["https://evil.com", "https://victim.com"])
            .validate()
            .is_err(),
        "rp_id=com 不得让任意 *.com 通过 origin 校验"
    );
}

/// 多标签 rp_id 正常工作，子域仍然是合法 origin。
#[test]
fn registrable_rp_id_accepts_itself_and_subdomains() {
    let setting = setting(
        "example.com",
        &["https://example.com", "https://login.example.com"],
    )
    .validate()
    .expect("registrable rp_id");
    assert_eq!(setting.rp_id, "example.com");
    assert_eq!(
        setting.allowed_origins,
        vec![
            "https://example.com".to_owned(),
            "https://login.example.com".to_owned()
        ]
    );
}

/// 保留的开发例外：`localhost` 及其子域可用，且回环允许 http。
///
/// `Config` 在缺少 `WEBAUTHN_RP_ID` 时会从 issuer host 填出这个值，去掉例外等于
/// 让默认本地部署起不来。
#[test]
fn localhost_remains_a_development_exception() {
    let setting = setting("localhost", &["http://localhost:5175"])
        .validate()
        .expect("localhost rp_id");
    assert_eq!(setting.rp_id, "localhost");
    assert_eq!(
        setting.allowed_origins,
        vec!["http://localhost:5175".to_owned()]
    );

    setting_with_subdomain()
        .validate()
        .expect("localhost subdomain origin");
}

fn setting_with_subdomain() -> PasskeySetting {
    let mut value = setting("localhost", &["http://app.localhost:5175"]);
    // `*.localhost` 同样由 RFC 6761 保证指向回环，但它不是回环字面量，
    // 因此需要显式允许明文 origin。
    value.allow_insecure_origin = true;
    value
}

/// 非同域 origin 仍然被拒：后缀规则不能被「像子域的域名」骗过。
#[test]
fn origin_must_match_the_registrable_rp_id() {
    for origin in [
        "https://example.com.evil.com",
        "https://notexample.com",
        "https://example.org",
    ] {
        assert!(
            setting("example.com", &[origin]).validate().is_err(),
            "{origin} 不属于 example.com，必须拒绝"
        );
    }
}

/// rp_id 形态本身的既有约束不能因为新规则丢掉。
#[test]
fn malformed_rp_id_stays_rejected() {
    for rp_id in [
        "",
        "   ",
        ".example.com",
        "example.com.",
        "example..com",
        "exa mple.com",
        "example.com/path",
        "user@example.com",
    ] {
        assert!(
            setting(rp_id, &["https://login.example.com"])
                .validate()
                .is_err(),
            "rp_id={rp_id:?} 必须拒绝"
        );
    }
}
