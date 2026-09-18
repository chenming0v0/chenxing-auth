//! 快照解析的夹具一致性与恶意输入测试。

use serde_json::{Value, json};

use super::error::ProtocolError;
use super::fixtures;
use super::snapshot::{AccountSnapshot, AccountStatus, FieldValue, Subscription};

fn base_snapshot() -> Value {
    fixtures::value(fixtures::ACCOUNT_SNAPSHOT)
}

fn snapshot_with_subscription(subscription: Value) -> Value {
    let mut snapshot = base_snapshot();
    let _ = snapshot
        .as_object_mut()
        .expect("snapshot object")
        .insert("subscription".to_owned(), subscription);
    snapshot
}

#[test]
fn parses_the_shared_account_snapshot_fixture() {
    let snapshot = AccountSnapshot::parse(fixtures::ACCOUNT_SNAPSHOT.as_bytes()).expect("snapshot");
    assert_eq!(snapshot.issuer.as_str(), "https://provider.example.com");
    assert_eq!(snapshot.uid, "acct-1001");
    assert_eq!(snapshot.account, "demo-account-1001");
    assert_eq!(snapshot.name.as_deref(), Some("示例用户"));
    assert_eq!(snapshot.status, AccountStatus::Active);
    assert!(matches!(
        snapshot.subscription,
        Subscription::ExpiresAt { .. }
    ));
    assert_eq!(snapshot.fields.len(), 7);
    assert_eq!(
        snapshot.fields[0].value,
        FieldValue::Text("acct-1001".to_owned())
    );
    assert_eq!(snapshot.fields[2].value, FieldValue::Boolean(true));
    assert_eq!(snapshot.fields[4].value, FieldValue::Duration(9_071_999));
    assert!(matches!(&snapshot.fields[6].value, FieldValue::Url(_)));
}

#[test]
fn unknown_top_level_fields_are_ignored_and_unknown_field_types_are_dropped() {
    let snapshot = AccountSnapshot::parse(fixtures::SNAPSHOT_UNKNOWN.as_bytes()).expect("snapshot");
    assert_eq!(snapshot.name, None);
    assert_eq!(snapshot.status, AccountStatus::Unknown);
    assert_eq!(snapshot.subscription, Subscription::Unknown);
    // `unmapped_field` 的 type 未知，必须被真正丢弃，且不按对象渲染。
    assert_eq!(snapshot.fields.len(), 1);
    assert_eq!(snapshot.fields[0].key, "uid");
}

#[test]
fn invalid_subscription_cases_match_the_shared_fixture() {
    let cases = fixtures::value(fixtures::INVALID_SUBSCRIPTIONS);
    let cases = cases
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases array");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case.get("name").and_then(Value::as_str).expect("case name");
        let expect = case.get("expect").and_then(Value::as_str).expect("expect");
        let subscription = case.get("subscription").expect("subscription").clone();
        let result = AccountSnapshot::from_value(&snapshot_with_subscription(subscription));
        match expect {
            "reject" => assert!(result.is_err(), "case `{name}` must be rejected"),
            "accept" => assert!(result.is_ok(), "case `{name}` must be accepted"),
            other => panic!("unexpected expectation `{other}`"),
        }
    }
}

#[test]
fn unknown_subscription_kind_never_becomes_permanent_or_none() {
    let error = AccountSnapshot::from_value(&snapshot_with_subscription(json!({
        "kind": "future_kind",
        "expires_at": "2026-12-31T23:59:59Z",
    })))
    .expect_err("unknown kind");
    assert_eq!(error, ProtocolError::UnknownSubscriptionKind);

    let none_null = AccountSnapshot::from_value(&snapshot_with_subscription(json!({
        "kind": "none",
        "expires_at": null,
    })))
    .expect_err("null expiry is not `none`");
    assert_eq!(none_null, ProtocolError::SubscriptionFieldConflict);
}

#[test]
fn duplicate_field_keys_are_rejected() {
    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "dup", "label": "A", "type": "text", "value": "a" },
        { "key": "dup", "label": "B", "type": "text", "value": "b" },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("duplicate key"),
        ProtocolError::DuplicateFieldKey
    );
}

#[test]
fn key_uniqueness_covers_entries_with_unknown_types() {
    // 第二条 type 未知会被丢弃，但它的 key 仍占用唯一性名额，必须先于丢弃被检出。
    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "dup", "label": "A", "type": "text", "value": "a" },
        { "key": "dup", "label": "B", "type": "vendor_future_type", "value": { "x": 1 } },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("duplicate unknown-typed key"),
        ProtocolError::DuplicateFieldKey
    );
}

#[test]
fn field_keys_must_match_the_schema_pattern() {
    for key in [
        "Upper",
        "1leading",
        "has space",
        "has/slash",
        "has@at",
        "has:colon",
        "汉字",
        "",
    ] {
        let mut snapshot = base_snapshot();
        snapshot["fields"] = json!([
            { "key": key, "label": "L", "type": "text", "value": "v" },
        ]);
        assert!(
            AccountSnapshot::from_value(&snapshot).is_err(),
            "key `{key}` must be rejected"
        );
    }
    for key in ["a", "a.b-c_d", "account_status", "k0"] {
        let mut snapshot = base_snapshot();
        snapshot["fields"] = json!([
            { "key": key, "label": "L", "type": "text", "value": "v" },
        ]);
        assert!(
            AccountSnapshot::from_value(&snapshot).is_ok(),
            "key `{key}` must be accepted"
        );
    }
}

#[test]
fn entry_point_enforces_the_128_kib_limit() {
    let oversized = vec![b' '; super::scalar::MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        AccountSnapshot::parse(&oversized).expect_err("oversized"),
        ProtocolError::PayloadTooLarge
    );
}

#[test]
fn more_than_sixty_four_fields_are_rejected() {
    let mut snapshot = base_snapshot();
    let fields: Vec<Value> = (0..65)
        .map(|index| json!({ "key": format!("k{index}"), "label": "L", "type": "text", "value": "v" }))
        .collect();
    snapshot["fields"] = Value::Array(fields);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("too many fields"),
        ProtocolError::TooManyFields
    );
}

#[test]
fn byte_limits_are_enforced_on_utf8_not_code_points() {
    let mut snapshot = base_snapshot();
    // 43 个汉字 = 129 UTF-8 字节，但只有 43 个码点。
    let long_key = "汉".repeat(43);
    snapshot["fields"] = json!([
        { "key": long_key, "label": "L", "type": "text", "value": "v" },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("key bytes"),
        ProtocolError::ByteLimitExceeded("field.key")
    );

    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "k", "label": "L", "type": "text", "value": "x".repeat(513) },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("text bytes"),
        ProtocolError::ByteLimitExceeded("field.value")
    );
}

#[test]
fn unsafe_urls_and_malicious_numbers_are_rejected() {
    for url in [
        "http://provider.example.com/x",
        "https://user:pass@provider.example.com/x",
    ] {
        let mut snapshot = base_snapshot();
        snapshot["fields"] = json!([
            { "key": "homepage", "label": "L", "type": "url", "value": url },
        ]);
        assert!(
            AccountSnapshot::from_value(&snapshot).is_err(),
            "url `{url}` must be rejected"
        );
    }

    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "n", "label": "L", "type": "number", "value": 9_007_199_254_740_992_i64 },
    ]);
    assert!(
        AccountSnapshot::from_value(&snapshot).is_err(),
        "number over safe range"
    );

    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "d", "label": "L", "type": "duration", "value": 1.5 },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("fractional duration"),
        ProtocolError::UnexpectedType("field.value")
    );

    let mut snapshot = base_snapshot();
    snapshot["fields"] = json!([
        { "key": "b", "label": "L", "type": "boolean", "value": "true" },
    ]);
    assert_eq!(
        AccountSnapshot::from_value(&snapshot).expect_err("string boolean"),
        ProtocolError::UnexpectedType("field.value")
    );
}

#[test]
fn snapshot_rebuild_is_parseable_and_stays_truthful() {
    let snapshot = AccountSnapshot::parse(fixtures::ACCOUNT_SNAPSHOT.as_bytes()).expect("snapshot");
    let rebuilt = AccountSnapshot::from_value(&snapshot.to_value()).expect("rebuilt snapshot");
    assert_eq!(rebuilt, snapshot);
}
