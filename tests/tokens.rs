use chenxing_auth::keys::KeyManager;
use chenxing_auth::oauth::{
    id_token::{IdTokenClaims, IdTokenProfile, issue_id_token, issue_id_token_with_profile},
    token::{AccessTokenClaims, decode_access_token, issue_access_token},
};

#[test]
fn access_token_is_signed_with_current_key_and_contains_scope() {
    let keys = KeyManager::generate().expect("signing key");
    let token = issue_access_token(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned(), "profile".to_owned()],
        3600,
    )
    .expect("access token");

    let header = jsonwebtoken::decode_header(&token).expect("JWT header");
    assert_eq!(header.kid.as_deref(), Some(keys.key_id().as_str()));
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
}

#[test]
fn expired_access_token_is_rejected_without_clock_leeway() {
    let keys = KeyManager::generate().expect("signing key");
    let now = usize::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .expect("current timestamp");
    let claims = AccessTokenClaims {
        iss: "https://auth.example.com".to_owned(),
        sub: "user-1".to_owned(),
        aud: "cx_project".to_owned(),
        exp: now
            .checked_sub(1)
            .expect("current timestamp is after epoch"),
        iat: now
            .checked_sub(2)
            .expect("current timestamp is after epoch"),
        scope: "openid".to_owned(),
    };
    let signing_key = keys.active_signing_key().expect("active signing key");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(signing_key.key_id().to_owned());
    let token = jsonwebtoken::encode(&header, &claims, signing_key.encoding_key())
        .expect("expired access token");

    assert!(
        decode_access_token(&keys, "https://auth.example.com", "cx_project", &token).is_err(),
        "an access token must be rejected immediately after exp"
    );
}

fn id_token_validation() -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    // Keep test-side OIDC validation aligned with the service's explicit expiry policy.
    validation.leeway = 0;
    validation.set_issuer(&["https://auth.example.com"]);
    validation.set_audience(&["cx_project"]);
    validation
}

#[test]
fn id_token_contains_oidc_subject_audience_and_nonce() {
    let keys = KeyManager::generate().expect("signing key");
    let token = issue_id_token(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        Some("nonce-value"),
        3600,
    )
    .expect("ID token");
    let validation = id_token_validation();
    let claims = jsonwebtoken::decode::<chenxing_auth::oauth::id_token::IdTokenClaims>(
        &token,
        &keys.decoding_key().expect("decoding key"),
        &validation,
    )
    .expect("valid ID token")
    .claims;

    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.aud, "cx_project");
    assert_eq!(claims.nonce.as_deref(), Some("nonce-value"));
}

fn decode_id_token(token: &str, keys: &KeyManager) -> IdTokenClaims {
    let validation = id_token_validation();
    jsonwebtoken::decode::<IdTokenClaims>(
        token,
        &keys.decoding_key().expect("decoding key"),
        &validation,
    )
    .expect("valid ID token")
    .claims
}

/// 有会话时 `auth_time` 必须出现在 ID Token 中（OIDC Core §2 要求），
/// 且值必须是会话建立时间而不是签发时间。
#[test]
fn id_token_with_session_contains_auth_time() {
    let keys = KeyManager::generate().expect("signing key");
    // 使用一个固定的过去时间戳来验证值被正确传递。
    let session_created_at: i64 = 1_700_000_000;
    let token = issue_id_token_with_profile(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        IdTokenProfile {
            nonce: Some("nonce"),
            auth_time: Some(session_created_at),
            ..Default::default()
        },
        3600,
    )
    .expect("ID token");

    let claims = decode_id_token(&token, &keys);

    assert_eq!(
        claims.auth_time,
        Some(usize::try_from(session_created_at).expect("usize"))
    );
    // auth_time 必须是会话建立时间，不是 iat。
    assert_ne!(claims.auth_time, Some(claims.iat));
}

/// 无会话上下文（刷新令牌路径、降级路径）时 `auth_time` 键必须省略，
/// 不能以 `null` 写入 JWT payload（OIDC Core 5.1：不返回的 Claim 应省略）。
#[test]
fn id_token_without_session_omits_auth_time_key() {
    let keys = KeyManager::generate().expect("signing key");
    let token = issue_id_token_with_profile(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        IdTokenProfile {
            auth_time: None,
            ..Default::default()
        },
        3600,
    )
    .expect("ID token");

    let claims = decode_id_token(&token, &keys);

    assert!(claims.auth_time.is_none());

    // 解码 payload 验证 `null` 没有写入 JSON。
    let payload = token.split('.').nth(1).expect("JWT payload");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        .expect("base64 payload");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON payload");
    assert!(
        json.get("auth_time").is_none(),
        "auth_time must not appear in JWT payload when there is no session context"
    );
}
