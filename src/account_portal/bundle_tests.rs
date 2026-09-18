//! 令牌包解析与创建/刷新绑定的测试。

use serde_json::{Value, json};
use uuid::Uuid;

use super::bundle::{AccessToken, RefreshBinding, RefreshToken, TokenBundle};
use super::error::ProtocolError;
use super::fixtures;
use super::scalar::{Issuer, UtcTime};

const BINDING_ID: &str = "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f";
const GRANT_ID: &str = "9f0c2b7e-3d41-4a88-b1c2-7e6f5d4c3b2a";
const ISSUER: &str = "https://provider.example.com";
const GRANT_EXPIRES_AT: &str = "2026-12-17T00:00:00Z";

fn issuer() -> Issuer {
    Issuer::parse(ISSUER).expect("issuer")
}

fn binding_id() -> Uuid {
    Uuid::parse_str(BINDING_ID).expect("binding id")
}

fn bundle_value(fixture: &str) -> Value {
    fixtures::value(fixture)
}

#[test]
fn parses_and_binds_a_creation_bundle() {
    let bundle = TokenBundle::parse(fixtures::LINK_SESSION_RESPONSE.as_bytes()).expect("bundle");
    bundle
        .validate_create(&issuer(), binding_id())
        .expect("create binding");
    assert_eq!(bundle.uid, "acct-1001");
    assert_eq!(bundle.scope, "account:read");
    assert_eq!(bundle.token_type, "Bearer");
    assert_eq!(
        bundle.grant_expires_at,
        UtcTime::parse_rfc3339(GRANT_EXPIRES_AT).expect("time")
    );
    assert!(bundle.access_token.expose().starts_with("cxap_at_"));
    assert!(bundle.refresh_token.expose().starts_with("cxap_rt_"));
    assert_eq!(bundle.snapshot.uid, bundle.uid);
}

#[test]
fn parses_and_binds_a_refresh_bundle_without_changing_grant_identity() {
    let bundle = TokenBundle::parse(fixtures::REFRESH_RESPONSE.as_bytes()).expect("bundle");
    let binding = RefreshBinding {
        grant_id: Uuid::parse_str(GRANT_ID).expect("grant id"),
        uid: "acct-1001",
        grant_expires_at: UtcTime::parse_rfc3339(GRANT_EXPIRES_AT).expect("time"),
    };
    bundle
        .validate_refresh(&issuer(), binding_id(), &binding)
        .expect("refresh binding");
}

#[test]
fn creation_and_refresh_validate_different_identities() {
    let bundle = TokenBundle::parse(fixtures::REFRESH_RESPONSE.as_bytes()).expect("bundle");
    // 刷新包可以过 create 的通用校验。
    assert!(bundle.validate_create(&issuer(), binding_id()).is_ok());
    // 但刷新绑定必须匹配 grant 身份。
    let wrong_grant = RefreshBinding {
        grant_id: Uuid::new_v4(),
        uid: "acct-1001",
        grant_expires_at: UtcTime::parse_rfc3339(GRANT_EXPIRES_AT).expect("time"),
    };
    assert_eq!(
        bundle
            .validate_refresh(&issuer(), binding_id(), &wrong_grant)
            .expect_err("grant mismatch"),
        ProtocolError::GrantMismatch
    );
    let wrong_uid = RefreshBinding {
        grant_id: Uuid::parse_str(GRANT_ID).expect("grant id"),
        uid: "acct-9999",
        grant_expires_at: UtcTime::parse_rfc3339(GRANT_EXPIRES_AT).expect("time"),
    };
    assert_eq!(
        bundle
            .validate_refresh(&issuer(), binding_id(), &wrong_uid)
            .expect_err("uid mismatch"),
        ProtocolError::UidMismatch
    );
    let wrong_expiry = RefreshBinding {
        grant_id: Uuid::parse_str(GRANT_ID).expect("grant id"),
        uid: "acct-1001",
        grant_expires_at: UtcTime::parse_rfc3339("2027-01-01T00:00:00Z").expect("time"),
    };
    assert_eq!(
        bundle
            .validate_refresh(&issuer(), binding_id(), &wrong_expiry)
            .expect_err("grant expiry mismatch"),
        ProtocolError::GrantExpiryMismatch
    );
}

#[test]
fn issuer_binding_and_snapshot_mismatches_are_rejected() {
    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["issuer"] = json!("https://evil.example.com");
    let bundle = TokenBundle::from_value(&value).expect("parsed");
    assert_eq!(
        bundle
            .validate_create(&issuer(), binding_id())
            .expect_err("issuer"),
        ProtocolError::IssuerMismatch
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["client_binding_id"] = json!(Uuid::new_v4().to_string());
    let bundle = TokenBundle::from_value(&value).expect("parsed");
    assert_eq!(
        bundle
            .validate_create(&issuer(), binding_id())
            .expect_err("binding"),
        ProtocolError::BindingMismatch
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["snapshot"]["uid"] = json!("acct-other");
    let bundle = TokenBundle::from_value(&value).expect("parsed");
    assert_eq!(
        bundle
            .validate_create(&issuer(), binding_id())
            .expect_err("snapshot uid"),
        ProtocolError::SnapshotUidMismatch
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["snapshot"]["issuer"] = json!("https://other.example.com");
    let bundle = TokenBundle::from_value(&value).expect("parsed");
    assert_eq!(
        bundle
            .validate_create(&issuer(), binding_id())
            .expect_err("snapshot issuer"),
        ProtocolError::SnapshotIssuerMismatch
    );
}

#[test]
fn protocol_scope_tokens_and_lifetimes_are_strictly_validated() {
    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["scope"] = json!("account:write");
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("scope"),
        ProtocolError::ScopeMismatch
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["protocol"] = json!("oauth2");
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("protocol"),
        ProtocolError::ProtocolMismatch
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["access_token"] = json!("opaque-token");
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("access token prefix"),
        ProtocolError::InvalidAccessToken
    );

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["refresh_expires_at"] = json!("2027-06-01T00:00:00Z");
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("refresh window"),
        ProtocolError::RefreshExpiryExceedsGrant
    );

    assert!(AccessToken::parse("cxap_at_").is_err());
}

#[test]
fn expires_in_must_not_exceed_the_protocol_baseline() {
    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["expires_in"] = json!(900);
    assert!(TokenBundle::from_value(&value).is_ok());

    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["expires_in"] = json!(901);
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("expires_in cap"),
        ProtocolError::InvalidValue("expires_in")
    );

    // 之前的 9e15 会通过 u64 校验，随后让时间计算溢出。
    let mut value = bundle_value(fixtures::LINK_SESSION_RESPONSE);
    value["expires_in"] = json!(9_000_000_000_000_000_u64);
    assert_eq!(
        TokenBundle::from_value(&value).expect_err("huge expires_in"),
        ProtocolError::InvalidValue("expires_in")
    );
}

#[test]
fn tokens_reject_whitespace_and_control_characters_but_keep_any_encoding() {
    for token in [
        "cxap_at_has space",
        "cxap_at_has\ttab",
        "cxap_at_has\nnewline",
        "cxap_rt_has space",
    ] {
        assert!(
            AccessToken::parse(token).is_err() && RefreshToken::parse(token).is_err(),
            "token `{token}` must be rejected"
        );
    }
    // 不擅自限制成某一种随机编码：URL-safe、标准 base64 与任意可见 ASCII 都接受。
    for token in [
        "cxap_at_AbC-_.~0123456789",
        "cxap_at_AbC+/=0123456789",
        "cxap_at_0000000000000000",
    ] {
        assert!(AccessToken::parse(token).is_ok(), "token `{token}`");
    }
}

#[test]
fn refresh_must_not_be_bound_to_a_textually_different_issuer() {
    // 显式默认端口是合法输入，但原文不同就不是同一个 issuer。
    let explicit_port = Issuer::parse("https://provider.example.com:443").expect("issuer");
    let bundle = TokenBundle::parse(fixtures::LINK_SESSION_RESPONSE.as_bytes()).expect("bundle");
    assert_eq!(
        bundle
            .validate_create(&explicit_port, binding_id())
            .expect_err("textually different issuer"),
        ProtocolError::IssuerMismatch
    );
}

#[test]
fn storage_export_round_trips_the_verified_values() {
    let bundle = TokenBundle::parse(fixtures::LINK_SESSION_RESPONSE.as_bytes()).expect("bundle");
    let storage = bundle.to_storage_plaintext();
    let value: Value = serde_json::from_str(storage.expose()).expect("storage json");
    assert_eq!(value["issuer"], json!(ISSUER));
    assert_eq!(value["access_token"], json!(bundle.access_token.expose()));
    assert_eq!(value["refresh_token"], json!(bundle.refresh_token.expose()));
    assert_eq!(value["uid"], json!(bundle.uid));
    assert_eq!(value["grant_expires_at"], json!(GRANT_EXPIRES_AT));
}

#[test]
fn entry_point_enforces_the_128_kib_limit() {
    let oversized = vec![b' '; super::scalar::MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        TokenBundle::parse(&oversized).expect_err("oversized"),
        ProtocolError::PayloadTooLarge
    );
}

#[test]
fn debug_and_storage_exports_do_not_leak_tokens_by_accident() {
    let bundle = TokenBundle::parse(fixtures::LINK_SESSION_RESPONSE.as_bytes()).expect("bundle");
    let debug = format!("{bundle:?}");
    assert!(!debug.contains(bundle.access_token.expose()));
    assert!(!debug.contains(bundle.refresh_token.expose()));

    // 显式导出是唯一写明文路径，且返回 `SecretString`。
    let storage = bundle.to_storage_plaintext();
    assert!(storage.expose().contains(bundle.access_token.expose()));
    assert!(!format!("{storage:?}").contains(bundle.access_token.expose()));
}
