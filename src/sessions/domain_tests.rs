use super::{
    Session, SessionPayload, decode_session_token_hash, generate_credential,
    session_token_hash, session_token_hash_bytes,
};
use std::time::Duration;
use time::OffsetDateTime;

#[test]
fn credentials_are_random_and_hashable_without_exposing_plaintext() {
    let first = generate_credential();
    let second = generate_credential();
    assert_ne!(first.token, second.token);
    assert_eq!(first.token.len(), 43);
    assert_ne!(first.token_hash, [0; 32]);
}

#[test]
fn session_token_hash_uses_a_fixed_digest_encoding() {
    let token = "session-token";
    let encoded = session_token_hash(token);

    assert_ne!(encoded, token);
    assert_eq!(encoded.len(), 43);
    assert_eq!(
        decode_session_token_hash(&encoded),
        Some(session_token_hash_bytes(token))
    );
}

#[test]
fn new_session_starts_without_an_internal_database_id() {
    let session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
    assert_eq!(session.id, 0);
    assert!(!session.token.is_empty());
}

#[test]
fn new_session_uses_the_supplied_creation_time() {
    let created_at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(123);
    let session = Session::new_at("1".to_owned(), Duration::from_secs(60), created_at).unwrap();

    assert_eq!(session.created_at, created_at);
    assert_eq!(session.expires_at, created_at + time::Duration::seconds(60));
    assert_eq!(session.last_seen_at, created_at);
}

/// 43 字符的 base64url 令牌，与 `Session::new` 生成的 CSRF 令牌长度一致。
const CSRF_TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

fn session_with_csrf(csrf_token: &str) -> Session {
    let mut session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
    session.csrf_token = csrf_token.to_owned();
    session
}

/// 常量时间比较的注释假设 CSRF 令牌长度是固定的公开参数，这里锁定该不变量。
#[test]
fn generated_csrf_token_has_a_fixed_public_length() {
    let session = Session::new("1".to_owned(), Duration::from_secs(60)).unwrap();
    assert_eq!(session.csrf_token.len(), 43);
    assert_eq!(CSRF_TOKEN.len(), session.csrf_token.len());
}

#[test]
fn csrf_validation_accepts_the_matching_token() {
    let session = session_with_csrf(CSRF_TOKEN);
    assert!(session.validates_csrf(CSRF_TOKEN));
}

#[test]
fn csrf_validation_rejects_a_different_token_of_the_same_length() {
    let session = session_with_csrf(CSRF_TOKEN);
    assert!(!session.validates_csrf("GFEDCBA9876543210zyxwvutsrqponmlkjihgfedcba"));
}

#[test]
fn csrf_validation_rejects_an_empty_token() {
    let session = session_with_csrf(CSRF_TOKEN);
    assert!(!session.validates_csrf(""));
}

#[test]
fn csrf_validation_rejects_an_empty_token_even_when_the_session_has_none() {
    // 会话侧令牌异常缺失时，空头部也不能被判定为相等。
    let session = session_with_csrf("");
    assert!(!session.validates_csrf(""));
}

#[test]
fn csrf_validation_rejects_tokens_with_a_different_length() {
    let session = session_with_csrf(CSRF_TOKEN);
    assert!(!session.validates_csrf(&CSRF_TOKEN[..CSRF_TOKEN.len() - 1]));
    assert!(!session.validates_csrf(&format!("{CSRF_TOKEN}H")));
}

/// 校验不是前缀匹配：只差首字符或末字符都必须拒绝。
#[test]
fn csrf_validation_rejects_tokens_differing_in_a_single_character() {
    let session = session_with_csrf(CSRF_TOKEN);
    let mut last_differs = CSRF_TOKEN.to_owned();
    last_differs.pop();
    last_differs.push('H');
    assert!(!session.validates_csrf(&last_differs));

    let first_differs = format!("X{}", &CSRF_TOKEN[1..]);
    assert_eq!(first_differs.len(), CSRF_TOKEN.len());
    assert!(!session.validates_csrf(&first_differs));
}

/// 构造升级前的载荷 JSON：`SessionPayload` 的字段加上当时存在的明文 `token`。
///
/// 不写死时间戳字面量——`time` 只启用了 `serde` 特性（没有 `serde-human-readable`），
/// `OffsetDateTime` 的序列化形式不是 RFC 3339 字符串，硬编码字面量会与实际格式失配。
fn legacy_payload_json(session: &Session) -> String {
    let mut value =
        serde_json::to_value(SessionPayload::from(session)).expect("payload as JSON value");
    value
        .as_object_mut()
        .expect("payload serializes to a JSON object")
        .remove("last_seen_at");
    value
        .as_object_mut()
        .expect("payload serializes to a JSON object")
        .insert(
            "token".to_owned(),
            serde_json::Value::String(session.token.clone()),
        );
    value.to_string()
}

/// 载荷不得携带明文会话令牌：密钥与数据库备份同时泄露时，
/// 攻击者只能拿到 token_hash，无法反推出可用令牌。
#[test]
fn serialized_payload_never_contains_the_plaintext_session_token() {
    let session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
    let payload = SessionPayload::from(&session);

    let value = serde_json::to_value(&payload).expect("payload as JSON value");
    assert!(value.get("token").is_none());
    assert!(!serde_json::to_string(&payload)
        .expect("serialize payload")
        .contains(&session.token));
    // csrf_token 必须继续持久化：find() 依赖它完成双提交校验。
    assert_eq!(
        value.get("csrf_token").and_then(serde_json::Value::as_str),
        Some(session.csrf_token.as_str())
    );
}

/// 向后兼容回归：升级前写入的载荷含 `token` 字段。`SessionPayload` 未标注
/// `deny_unknown_fields`，serde 必须忽略这个多余字段而不是报错，
/// 否则升级后所有历史会话都会解析失败而被判定为不存在。
#[test]
fn legacy_payload_containing_a_token_field_is_still_readable() {
    let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
    session.id = 7;
    let legacy_json = legacy_payload_json(&session);
    // 前置条件：构造出的旧载荷确实含明文令牌，否则这个回归测试没有意义。
    assert!(legacy_json.contains(&session.token));

    let payload: SessionPayload =
        serde_json::from_str(&legacy_json).expect("legacy payload must remain readable");

    assert_eq!(payload.id, 7);
    assert_eq!(payload.user_id, "42");
    assert_eq!(payload.csrf_token, session.csrf_token);
    assert_eq!(payload.created_at, session.created_at);
    assert_eq!(payload.expires_at, session.expires_at);
    assert!(payload.last_seen_at.is_none());
    assert!(payload.revoked_at.is_none());

    // 令牌只从请求来：旧载荷里的明文令牌被忽略，由调用方传入值填回。
    let restored = payload.into_session("token-from-request".to_owned());
    assert_eq!(restored.token, "token-from-request");
    assert_ne!(restored.token, session.token);
    assert!(restored.validates_csrf(&session.csrf_token));
}

/// 归一化后的旧载荷不再含明文令牌。outbox 投影到 Redis 走的是同一条
/// 「解析 + 重新序列化」路径，因此历史会话也不会在 Redis 留下可用令牌。
#[test]
fn legacy_payload_loses_its_token_when_reserialized() {
    let session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
    let legacy_json = legacy_payload_json(&session);
    let payload: SessionPayload = serde_json::from_str(&legacy_json).expect("legacy payload");

    let reserialized = serde_json::to_value(&payload).expect("reserialize payload");

    assert!(reserialized.get("token").is_none());
    assert!(!reserialized.to_string().contains(&session.token));
    assert_eq!(
        reserialized
            .get("csrf_token")
            .and_then(serde_json::Value::as_str),
        Some(session.csrf_token.as_str())
    );
}

/// 存储往返：除令牌外的字段必须原样恢复，令牌由调用方补回。
#[test]
fn payload_round_trip_restores_every_field_except_the_token() {
    let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
    session.id = 99;
    let original = session.clone();

    let encoded = serde_json::to_vec(&SessionPayload::from(&session)).expect("serialize");
    let decoded: SessionPayload = serde_json::from_slice(&encoded).expect("deserialize");
    let restored = decoded.into_session(original.token.clone());

    assert_eq!(restored.id, original.id);
    assert_eq!(restored.token, original.token);
    assert_eq!(restored.user_id, original.user_id);
    assert_eq!(restored.created_at, original.created_at);
    assert_eq!(restored.expires_at, original.expires_at);
    assert_eq!(restored.last_seen_at, original.last_seen_at);
    assert_eq!(restored.csrf_token, original.csrf_token);
    assert_eq!(restored.revoked_at, original.revoked_at);
    assert!(restored.validates_csrf(&original.csrf_token));
}

/// 撤销时间戳属于持久化事实，必须往返保留。
#[test]
fn payload_round_trip_preserves_the_revocation_timestamp() {
    let mut session = Session::new("42".to_owned(), Duration::from_secs(60)).expect("session");
    session.revoke();

    let encoded = serde_json::to_vec(&SessionPayload::from(&session)).expect("serialize");
    let decoded: SessionPayload = serde_json::from_slice(&encoded).expect("deserialize");

    assert_eq!(decoded.revoked_at, session.revoked_at);
    assert!(!decoded.into_session(session.token.clone()).is_active());
}
