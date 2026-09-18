//! 请求构造与凭据脱敏测试。

use uuid::Uuid;

use super::bundle::RefreshToken;
use super::error::ProtocolError;
use super::fixtures;
use super::request::{
    CreateLinkSessionRequest, Credentials, MAX_CREDENTIAL_BYTES, RefreshLinkSessionRequest,
    RevokeLinkSessionRequest,
};

#[test]
fn credentials_enforce_byte_bounds() {
    assert!(Credentials::new("id", "secret").is_ok());
    assert_eq!(
        Credentials::new("", "secret").expect_err("empty identifier"),
        ProtocolError::InvalidCredentials
    );
    assert_eq!(
        Credentials::new("id", "").expect_err("empty secret"),
        ProtocolError::InvalidCredentials
    );
    assert_eq!(
        Credentials::new("x".repeat(MAX_CREDENTIAL_BYTES + 1), "secret")
            .expect_err("identifier over limit"),
        ProtocolError::InvalidCredentials
    );
}

#[test]
fn debug_output_never_contains_credentials_or_tokens() {
    let request =
        CreateLinkSessionRequest::new(Uuid::new_v4(), "pub-example-0001", "priv-example-0001")
            .expect("request");
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("pub-example-0001"));
    assert!(!rendered.contains("priv-example-0001"));

    let token =
        RefreshToken::parse("cxap_rt_AgICAgICAgICAgICAgICAgICAgICAgICAgICA").expect("token");
    let refresh = RefreshLinkSessionRequest::new(Uuid::new_v4(), token);
    let rendered = format!("{refresh:?}");
    assert!(!rendered.contains("cxap_rt_"));
}

#[test]
fn random_bindings_are_unique_and_fixture_ids_are_accepted() {
    let first = CreateLinkSessionRequest::with_random_binding("a", "b").expect("first");
    let second = CreateLinkSessionRequest::with_random_binding("a", "b").expect("second");
    assert_ne!(first.client_binding_id(), second.client_binding_id());

    // 共享夹具里的请求体必须在消费方约束下可用。
    let link = fixtures::value(fixtures::LINK_SESSION_REQUEST);
    let identifier = link["credentials"]["identifier"]
        .as_str()
        .expect("identifier");
    let secret = link["credentials"]["secret"].as_str().expect("secret");
    let binding = link["client_binding_id"].as_str().expect("binding");
    CreateLinkSessionRequest::new(Uuid::parse_str(binding).expect("uuid"), identifier, secret)
        .expect("fixture request");

    let revoke = fixtures::value(fixtures::REVOKE_REQUEST);
    RevokeLinkSessionRequest::new(
        Uuid::parse_str(revoke["client_binding_id"].as_str().expect("binding")).expect("uuid"),
    );

    let refresh = fixtures::value(fixtures::REFRESH_REQUEST);
    RefreshToken::parse(refresh["refresh_token"].as_str().expect("token")).expect("fixture token");
}
