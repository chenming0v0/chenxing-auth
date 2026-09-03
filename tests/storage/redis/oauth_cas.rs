//! Rolling-upgrade CAS identity for OAuth Redis credentials (issue #468).
//!
//! An older process deserializes a newer payload, drops unknown fields, and
//! must still consume/rotate/replace against the original Redis bytes. CAS
//! identity is the natural key plus `cas_revision`, not the complete JSON.

use base64::Engine;
use chenxing_auth::{
    oauth::{
        code::AuthorizationCode,
        consent::PendingAuthorization,
        quota::{OAuthQuotaStore, QuotaConsumeResult},
        refresh::RefreshToken,
        refresh_store::{RefreshTokenStore, RotationOutcome},
        request_store::AuthorizationRequestStore,
        store::AuthorizationCodeStore,
    },
    plans::domain::AuthQuotaLimits,
    redis_keyspace::RedisKeyspace,
};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn redis_client() -> redis::Client {
    redis::Client::open(redis_url()).expect("Redis URL")
}

fn keyspace(label: &str) -> RedisKeyspace {
    RedisKeyspace::new(&format!("{label}-{}", Uuid::new_v4().simple()))
        .expect("test Redis namespace")
}

async fn inject_future_field(key: &str, field: &str, value: serde_json::Value) {
    let mut connection = redis_client()
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let payload: String = connection.get(key).await.expect("stored JSON");
    let mut json: serde_json::Value = serde_json::from_str(&payload).expect("parse JSON");
    json[field] = value;
    let _: () = connection
        .set_ex(key, serde_json::to_string(&json).expect("encode JSON"), 60)
        .await
        .expect("inject future field");
}

fn pending(request_id: String, client_id: &str) -> PendingAuthorization {
    PendingAuthorization {
        request_id,
        client_id: client_id.to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "state".to_owned(),
        prompt: None,
        max_age: None,
        reauth_session_token_hash: None,
        reauth_required: false,
        nonce: None,
        code_challenge: "challenge".to_owned(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: None,
        holder_hash: None,
        issuer_generation: None,
        cas_revision: 0,
    }
}

fn hashed_code_key(keyspace: &RedisKeyspace, value: &str) -> String {
    keyspace.key(&format!(
        "chenxing:oauth:code:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    ))
}

fn hashed_refresh_key(keyspace: &RedisKeyspace, value: &str) -> String {
    keyspace.key(&format!(
        "chenxing:oauth:refresh:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    ))
}

#[tokio::test]
async fn old_model_can_consume_authorization_code_written_with_future_fields() {
    let keyspace = keyspace("cas-code");
    let store = AuthorizationCodeStore::with_keyspace(redis_client(), keyspace.clone());
    let quotas = OAuthQuotaStore::with_keyspace(redis_client(), keyspace.clone());
    let client_id = format!("cas-code-{}", Uuid::new_v4().simple());
    let now = OffsetDateTime::now_utc();
    let consumption = quotas
        .consume_with_limits_and_reservation_at(
            &client_id,
            AuthQuotaLimits {
                daily_auth_limit: 10,
                monthly_auth_limit: Some(20),
            },
            now,
        )
        .await
        .expect("reserve quota");
    assert_eq!(consumption.result, QuotaConsumeResult::Allowed);
    let reservation = consumption.reservation().expect("quota reservation");
    quotas
        .schedule_refund(&reservation, now + Duration::seconds(60))
        .await
        .expect("schedule refund");

    let mut code = AuthorizationCode::new(
        client_id.clone(),
        "https://cas.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    code.quota_reservation_id = Some(reservation.id().to_owned());
    store.save(&code).await.expect("save code");
    inject_future_field(
        &hashed_code_key(&keyspace, &code.value),
        "future_field",
        serde_json::json!({"version": 2}),
    )
    .await;

    let loaded = store
        .find(&code.value)
        .await
        .expect("find code")
        .expect("code still present");
    assert_eq!(loaded.cas_revision, 0);
    assert_eq!(loaded.value, code.value);

    let mismatched = AuthorizationCode::new(
        code.client_id.clone(),
        code.redirect_uri.clone(),
        code.user_id.clone(),
        code.scopes.clone(),
        "other-challenge".to_owned(),
    );
    assert!(
        !store
            .take_if_matches(&code.value, &mismatched)
            .await
            .expect("foreign identity must miss")
    );

    assert!(
        store
            .take_if_matches_with_quota_cancel(
                &code.value,
                &loaded,
                Some(quotas.refund_cancel(reservation.id())),
            )
            .await
            .expect("legacy reader consumes future payload")
    );
    assert!(
        store
            .find(&code.value)
            .await
            .expect("find consumed code")
            .is_none()
    );
    assert_eq!(
        quotas
            .run_refund_worker_pass(now + Duration::seconds(120))
            .await
            .expect("refund worker"),
        0
    );
}

#[tokio::test]
async fn old_model_can_replace_and_take_pending_written_with_future_fields() {
    let keyspace = keyspace("cas-pending");
    let store = AuthorizationRequestStore::with_keyspace(redis_client(), keyspace.clone());
    let request = pending(
        format!("pending-cas-{}", Uuid::new_v4().simple()),
        &format!("pending-cas-client-{}", Uuid::new_v4().simple()),
    );
    store.save(&request).await.expect("save pending");
    let key = keyspace.key(&format!("chenxing:oauth:request:{}", request.request_id));
    inject_future_field(&key, "future_field", serde_json::json!({"version": 2})).await;

    let loaded = store
        .find(&request.request_id)
        .await
        .expect("find pending")
        .expect("pending still present");
    assert_eq!(loaded.cas_revision, 0);

    let mut replacement = loaded.clone();
    replacement.session_token_hash = Some("rebound-session".to_owned());
    assert!(
        store
            .replace_if_matches(&request.request_id, &loaded, &replacement)
            .await
            .expect("replace pending with future field")
    );

    let rebound = store
        .find(&request.request_id)
        .await
        .expect("find rebound pending")
        .expect("rebound pending");
    assert_eq!(rebound.cas_revision, 1);
    assert_eq!(
        rebound.session_token_hash.as_deref(),
        Some("rebound-session")
    );
    assert!(
        !store
            .replace_if_matches(&request.request_id, &loaded, &replacement)
            .await
            .expect("stale revision must miss")
    );

    inject_future_field(&key, "another_future_field", serde_json::json!(true)).await;
    let current = store
        .find(&request.request_id)
        .await
        .expect("find current pending")
        .expect("current pending");
    assert!(
        store
            .take_if_matches(&request.request_id, &current)
            .await
            .expect("take pending with future field")
            .is_some()
    );
}

#[tokio::test]
async fn old_model_can_rotate_refresh_token_written_with_future_fields() {
    let keyspace = keyspace("cas-refresh");
    let store = RefreshTokenStore::with_keyspace(redis_client(), keyspace.clone());
    let token = RefreshToken::new(
        "cas-refresh-client".to_owned(),
        "cas-refresh-user".to_owned(),
        vec!["openid".to_owned()],
    );
    store.save(&token).await.expect("save refresh");
    inject_future_field(
        &hashed_refresh_key(&keyspace, &token.value),
        "future_field",
        serde_json::json!(["v2"]),
    )
    .await;

    let loaded = store
        .find(&token.value)
        .await
        .expect("find refresh")
        .expect("refresh still present");
    assert_eq!(loaded.cas_revision, 0);

    let mismatched = RefreshToken::new(
        token.client_id.clone(),
        token.user_id.clone(),
        vec!["profile".to_owned()],
    );
    assert_eq!(
        store
            .rotate_if_matches(&token.value, &mismatched, &mismatched)
            .await
            .expect("foreign identity must miss"),
        RotationOutcome::CasMismatch
    );

    let successor = token.rotate(vec!["openid".to_owned()]);
    assert_eq!(
        store
            .rotate_if_matches(&token.value, &loaded, &successor)
            .await
            .expect("legacy reader rotates future payload"),
        RotationOutcome::Rotated
    );
    assert!(
        store
            .find(&token.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        store
            .find(&successor.value)
            .await
            .expect("find successor")
            .is_some()
    );
    assert!(
        store
            .read_tombstone(&token.value)
            .await
            .expect("read tombstone")
            .is_some(),
        "rotation must still write a replay tombstone"
    );
}

#[tokio::test]
async fn old_model_can_take_refresh_token_written_with_future_fields() {
    let keyspace = keyspace("cas-refresh-take");
    let store = RefreshTokenStore::with_keyspace(redis_client(), keyspace.clone());
    let token = RefreshToken::new(
        "cas-refresh-take-client".to_owned(),
        "cas-refresh-take-user".to_owned(),
        vec!["openid".to_owned()],
    );
    store.save(&token).await.expect("save refresh");
    inject_future_field(
        &hashed_refresh_key(&keyspace, &token.value),
        "future_field",
        serde_json::json!(["v2"]),
    )
    .await;

    let loaded = store
        .find(&token.value)
        .await
        .expect("find refresh")
        .expect("refresh still present");
    assert!(
        store
            .take_if_matches(&token.value, &loaded)
            .await
            .expect("legacy reader consumes future refresh")
    );
    assert!(
        store
            .read_tombstone(&token.value)
            .await
            .expect("read consumed tombstone")
            .is_some()
    );
}
