//! 元数据解析测试。

use serde_json::json;

use super::error::ProtocolError;
use super::fixtures;
use super::metadata::ProviderMetadata;

#[test]
fn parses_the_shared_metadata_fixture() {
    let metadata = ProviderMetadata::parse(fixtures::METADATA.as_bytes()).expect("metadata");
    assert_eq!(metadata.protocol, "account-provider/v1");
    assert_eq!(metadata.issuer.as_str(), "https://provider.example.com");
    assert!(metadata.supports_account_read());
    assert_eq!(metadata.credentials.identifier_label, "账户");
    assert_eq!(metadata.credentials.secret_label, "密码");
    assert!(metadata.credentials.identifier_sensitive);
}

#[test]
fn unknown_top_level_fields_are_ignored() {
    let mut value = fixtures::value(fixtures::METADATA);
    let _ = value
        .as_object_mut()
        .expect("object")
        .insert("future".to_owned(), json!({ "ignored": true }));
    assert!(ProviderMetadata::from_value(&value).is_ok());
}

#[test]
fn protocol_and_capabilities_are_enforced() {
    let mut value = fixtures::value(fixtures::METADATA);
    value["protocol"] = json!("oauth2");
    assert_eq!(
        ProviderMetadata::from_value(&value).expect_err("protocol"),
        ProtocolError::ProtocolMismatch
    );

    let mut value = fixtures::value(fixtures::METADATA);
    value["capabilities"] = json!(["account:write"]);
    assert!(ProviderMetadata::from_value(&value).is_err());

    let mut value = fixtures::value(fixtures::METADATA);
    value["credentials"]["identifier_label"] = json!("汉".repeat(43));
    assert_eq!(
        ProviderMetadata::from_value(&value).expect_err("label bytes"),
        ProtocolError::ByteLimitExceeded("identifier_label")
    );
}

#[test]
fn credentials_is_exactly_three_description_keys() {
    let mut value = fixtures::value(fixtures::METADATA);
    value["credentials"]["extra_key"] = json!("not allowed");
    assert_eq!(
        ProviderMetadata::from_value(&value).expect_err("extra credentials key"),
        ProtocolError::InvalidValue("credentials")
    );

    let mut value = fixtures::value(fixtures::METADATA);
    let removed = value["credentials"]
        .as_object_mut()
        .expect("credentials object")
        .remove("secret_label");
    assert!(
        removed.is_some(),
        "test must remove the nested required key"
    );
    assert!(ProviderMetadata::from_value(&value).is_err());
}

#[test]
fn entry_point_enforces_the_128_kib_limit() {
    let oversized = vec![b' '; super::scalar::MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        ProviderMetadata::parse(&oversized).expect_err("oversized"),
        ProtocolError::PayloadTooLarge
    );
}
