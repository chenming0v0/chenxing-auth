use super::AuthorizationCode;
use crate::sessions::domain::session_token_hash;
use time::{Duration, OffsetDateTime};

fn code_with_session(session_token: Option<&str>) -> AuthorizationCode {
    AuthorizationCode::new_with_nonce(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        None,
        session_token.map(str::to_owned),
    )
}

#[test]
fn explicit_time_constructor_sets_creation_and_expiry_times() {
    let created_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(123);
    let code = AuthorizationCode::new_with_nonce_and_ttl_at(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        None,
        None,
        60,
        created_at,
    );

    assert_eq!(code.created_at, created_at);
    assert_eq!(code.expires_at, created_at + Duration::seconds(60));
}

/// 构造升级前的授权码 JSON：把当前的会话摘要键从载荷里删掉。
///
/// 不写死时间戳字面量——`time` 只启用了 `serde` 特性（没有
/// `serde-human-readable`），`OffsetDateTime` 的序列化形式不是 RFC 3339
/// 字符串，硬编码字面量会与实际格式失配。
fn legacy_code_json(code: &AuthorizationCode) -> String {
    let serialized = serde_json::to_string(code).expect("serialize code");
    let hash = serde_json::to_string(
        code.session_token_hash
            .as_ref()
            .expect("bound code has a session hash"),
    )
    .expect("serialize session hash");
    let field = format!("\"session_token_hash\":{hash}");
    let legacy = serialized.replace(&format!("{field},"), "");
    assert_ne!(legacy, serialized, "session hash field must be removed");
    legacy
}

/// 向后兼容回归：升级期间 Redis 里在途的授权码没有会话摘要键。
/// 少了 `#[serde(default)]` 就会反序列化失败，所有在途授权码直接作废。
#[test]
fn legacy_code_without_a_session_hash_deserializes_as_none() {
    let code = code_with_session(Some("session-token"));
    let legacy_json = legacy_code_json(&code);
    // 前置条件：构造出的旧载荷确实不含该键，否则这个回归测试没有意义。
    assert!(!legacy_json.contains("session_token_hash"));

    let restored: AuthorizationCode =
        serde_json::from_str(&legacy_json).expect("legacy code must remain readable");

    assert!(restored.session_token_hash.is_none());
    assert_eq!(restored.value, code.value);
    assert_eq!(restored.client_id, code.client_id);
    assert_eq!(restored.redirect_uri, code.redirect_uri);
    assert_eq!(restored.user_id, code.user_id);
    assert_eq!(restored.scopes, code.scopes);
    assert_eq!(restored.code_challenge, code.code_challenge);
    assert_eq!(restored.created_at, code.created_at);
    assert_eq!(restored.expires_at, code.expires_at);
}

/// `take_if_matches` 靠「重新序列化 == Redis 中的原始字符串」做原子消费。
/// 无会话的授权码必须省略该键而不是写成 `null`，否则旧授权码永远消费不掉。
#[test]
fn code_without_a_session_hash_round_trips_byte_identically() {
    let code = code_with_session(None);
    let payload = serde_json::to_string(&code).expect("serialize code");
    assert!(!payload.contains("session_token_hash"));

    let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

    assert_eq!(
        serde_json::to_string(&restored).expect("reserialize code"),
        payload
    );
}

/// 旧载荷解析后重新序列化不得带回会话摘要键或任何旧凭据。
#[test]
fn legacy_code_payload_reserializes_without_a_session_binding() {
    let legacy_json = legacy_code_json(&code_with_session(Some("session-token")));
    let restored: AuthorizationCode =
        serde_json::from_str(&legacy_json).expect("legacy code payload");

    let reserialized = serde_json::to_string(&restored).expect("reserialize legacy code");
    assert_eq!(reserialized, legacy_json);
    assert!(!reserialized.contains("session_token_hash"));
    assert!(!reserialized.contains("session-token"));
}

#[test]
fn legacy_plaintext_session_binding_is_rejected() {
    let mut value = serde_json::to_value(code_with_session(None)).expect("code as JSON value");
    value
        .as_object_mut()
        .expect("code serializes to a JSON object")
        .insert(
            "session_id".to_owned(),
            serde_json::Value::String("session-token".to_owned()),
        );
    let error = serde_json::from_value::<AuthorizationCode>(value)
        .expect_err("legacy plaintext session binding must be rejected");
    assert!(!error.to_string().contains("session-token"));
}

/// 有会话时摘要键必须真的写进载荷，否则 Token 端点拿不到会话、绑定形同虚设。
#[test]
fn code_with_a_session_hash_persists_without_plaintext() {
    let code = code_with_session(Some("session-token"));
    let payload = serde_json::to_string(&code).expect("serialize code");
    let hash = session_token_hash("session-token");
    assert!(payload.contains(&hash));
    assert!(!payload.contains("session-token"));

    let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

    assert_eq!(restored.session_token_hash.as_deref(), Some(hash.as_str()));
}

/// Issue #516：Issuer generation 是授权码的信任域边界。缺失值与其它
/// generation 都不能被当作当前 Issuer 的凭据。
#[test]
fn issuer_generation_binding_is_strict_and_legacy_payloads_fail_closed() {
    let code = code_with_session(Some("session-token")).with_issuer_generation(11);

    assert!(code.is_bound_to_issuer_generation(11));
    assert!(!code.is_bound_to_issuer_generation(12));

    let unbound = code_with_session(Some("session-token"));
    assert!(!unbound.is_bound_to_issuer_generation(11));
    assert!(unbound.issuer_generation.is_none());
}

/// Issue #516：新签发的授权码必须把 generation 写进 Redis 载荷。
#[test]
fn issuer_generation_is_persisted_when_present() {
    let code = code_with_session(Some("session-token")).with_issuer_generation(7);
    let payload = serde_json::to_string(&code).expect("serialize code");
    assert!(payload.contains("\"issuer_generation\":7"));

    let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");
    assert_eq!(restored.issuer_generation, Some(7));
    assert_eq!(
        serde_json::to_string(&restored).expect("reserialize bound code"),
        payload
    );
}

/// Issue #516：升级前 Redis 里没有 `issuer_generation` 的在途授权码必须仍可读，
/// 且重新序列化不得补上该键，否则 CAS 永远对不上旧载荷。
#[test]
fn legacy_code_without_issuer_generation_round_trips_without_the_field() {
    let code = code_with_session(Some("session-token")).with_issuer_generation(7);
    let serialized = serde_json::to_string(&code).expect("serialize code");
    let legacy = serialized.replace("\"issuer_generation\":7,", "");
    assert_ne!(
        legacy, serialized,
        "issuer generation field must be removed"
    );
    assert!(!legacy.contains("issuer_generation"));

    let restored: AuthorizationCode =
        serde_json::from_str(&legacy).expect("legacy code must remain readable");
    assert!(restored.issuer_generation.is_none());
    assert!(!restored.is_bound_to_issuer_generation(7));

    let reserialized = serde_json::to_string(&restored).expect("reserialize legacy code");
    assert_eq!(reserialized, legacy);
    assert!(!reserialized.contains("issuer_generation"));
}
