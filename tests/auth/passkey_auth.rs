use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use chenxing_auth::auth_limiter::FailureDimension;
use chenxing_auth::{
    auth_factors::domain::FactorMethod, sessions::cookies, state::AppState,
    users::domain::AuthenticatedUser,
};
use redis::AsyncCommands;
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{harness, http};

pub(super) async fn setup() -> (
    Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let harness = harness::HarnessBuilder::new("passkey_auth")
        .bootstrap_owner()
        .build()
        .await;
    let email = format!("passkey-{}@example.com", Uuid::new_v4().simple());
    (
        harness.router,
        harness.state,
        harness.database,
        harness.key_directory,
        email,
    )
}

pub(super) async fn post_with_cookie(
    router: &Router,
    uri: &str,
    body: serde_json::Value,
    cookie: &str,
) -> axum::response::Response {
    http::post_json_with_headers(router, uri, &[("cookie", cookie)], body).await
}

/// 逐个 ticket 的 Passkey 失败上限直接取自限流域模型，避免测试与实现漂移。
pub(super) fn ticket_failure_limit() -> usize {
    FailureDimension::Ticket.limit() as usize
}

pub(super) fn bogus_registration_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "",
        "rawId": "",
        "response": {"attestationObject": "", "clientDataJSON": ""},
        "type": "public-key"
    })
}

pub(super) fn bogus_authentication_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "",
        "rawId": "",
        "response": {
            "authenticatorData": "",
            "clientDataJSON": "",
            "signature": ""
        },
        "type": "public-key"
    })
}

pub(super) fn rotate_issuer_generation(state: &AppState) {
    state
        .issuer
        .apply(&chenxing_auth::settings::issuer::IssuerRecord {
            value: "http://127.0.0.1:3000".to_owned(),
            generation: 2,
            updated_at: time::OffsetDateTime::now_utc(),
        })
        .expect("rotate issuer generation");
}

fn test_passkey(credential_id: &[u8]) -> Passkey {
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": encode(credential_id),
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": encode(&[4; 32]),
                        "y": encode(&[5; 32])
                    }
                }
            },
            "counter": 0,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }
    }))
    .expect("test passkey")
}

pub(super) async fn insert_test_passkey(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    // 测试种数据直插 SQL，避免依赖已被移除的 repository::insert_passkey。
    // credential 必须是可解码的 Passkey JSON：authentication/start 会经 list_passkeys 反序列化。
    let credential =
        serde_json::to_value(test_passkey(&credential_id)).expect("serialize test passkey");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(credential)
    .execute(database)
    .await
    .expect("insert test passkey");
}

pub(super) async fn create_user(router: &Router, email: &str) -> String {
    let username = format!("passkey-limit-{}", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    username
}

pub(super) async fn login_ticket(
    state: &AppState,
    database: &chenxing_auth::sqlx::PgPool,
    email: &str,
) -> (String, String) {
    let (user_id, session_epoch): (i64, i64) =
        chenxing_auth::sqlx::query_as("SELECT id, session_epoch FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(database)
            .await
            .expect("user credentials");
    let holder = cookies::new_login_ticket_holder();
    let holder_hash = cookies::login_ticket_holder_hash(&holder);
    let (ticket_id, _) = state
        .factors
        .create_login_ticket(
            AuthenticatedUser::new(user_id, session_epoch),
            vec![FactorMethod::Passkey],
            &holder_hash,
        )
        .await
        .expect("login ticket");
    let cookie = format!(
        "{}={ticket_id}; {}={holder}",
        cookies::login_ticket_cookie_name(false),
        cookies::login_ticket_holder_cookie_name(false)
    );
    (ticket_id, cookie)
}

#[derive(Clone, Copy)]
pub(super) enum ExistingChallengeBehavior {
    Reject,
    Reuse,
}

/// #337：同一个 ticket 的 start 只能原子预留一份 challenge/state。
///
/// 注册 start 的并发败者和后续重复请求都必须明确拒绝；认证 start 则允许浏览器
/// 在取消 ceremony 后重试，但只能复用原 challenge。两条路径都不能改写胜者状态。
/// 删除 pending 后仍能用同一 ticket 重新 start，证明拒绝或幂等重试没有消耗或悬挂
/// 失败额度。
pub(super) async fn assert_start_reserves_one_challenge(
    router: &Router,
    endpoint: &str,
    ticket: &(String, String),
    pending_key: &str,
    existing_behavior: ExistingChallengeBehavior,
) {
    let (first, second) = tokio::join!(
        post_with_cookie(router, endpoint, serde_json::json!({}), &ticket.1),
        post_with_cookie(router, endpoint, serde_json::json!({}), &ticket.1),
    );
    let first_status = first.status();
    let second_status = second.status();
    let (winner, other) = match existing_behavior {
        ExistingChallengeBehavior::Reject => {
            if first_status == StatusCode::OK && second_status == StatusCode::BAD_REQUEST {
                (first, second)
            } else if second_status == StatusCode::OK && first_status == StatusCode::BAD_REQUEST {
                (second, first)
            } else {
                panic!(
                    "exactly one concurrent start must win, got {} and {}",
                    first_status, second_status
                );
            }
        }
        ExistingChallengeBehavior::Reuse => {
            assert_eq!(
                first_status,
                StatusCode::OK,
                "an authentication retry must return the reserved challenge"
            );
            assert_eq!(
                second_status,
                StatusCode::OK,
                "an authentication retry must return the reserved challenge"
            );
            (first, second)
        }
    };
    let winner_body = http::json_body(winner).await;
    let first_challenge = winner_body["publicKey"]["challenge"]
        .as_str()
        .expect("winner challenge")
        .to_owned();
    match existing_behavior {
        ExistingChallengeBehavior::Reject => assert_eq!(
            http::json_body(other).await["code"],
            "invalid_login_ticket",
            "the concurrent loser must be explicitly rejected"
        ),
        ExistingChallengeBehavior::Reuse => assert_eq!(
            http::json_body(other).await["publicKey"]["challenge"],
            first_challenge.as_str(),
            "an idempotent authentication retry must reuse the reserved challenge"
        ),
    }

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let reserved_payload: String = connection
        .get(pending_key)
        .await
        .expect("reserved passkey state");

    for _ in 0..=ticket_failure_limit() {
        let response = post_with_cookie(router, endpoint, serde_json::json!({}), &ticket.1).await;
        match existing_behavior {
            ExistingChallengeBehavior::Reject => {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    http::json_body(response).await["code"],
                    "invalid_login_ticket"
                );
            }
            ExistingChallengeBehavior::Reuse => {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    http::json_body(response).await["publicKey"]["challenge"],
                    first_challenge.as_str(),
                    "authentication retries must keep the reserved challenge"
                );
            }
        }
    }
    let payload_after_retries: String = connection
        .get(pending_key)
        .await
        .expect("passkey state after rejected starts");
    assert_eq!(
        payload_after_retries, reserved_payload,
        "a rejected or idempotent start retry must not overwrite the reserved challenge state"
    );

    let _: usize = connection
        .del(pending_key)
        .await
        .expect("release reserved passkey state");
    let response = post_with_cookie(router, endpoint, serde_json::json!({}), &ticket.1).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "rejected starts must not burn failure quota"
    );
    let replacement_challenge = http::json_body(response).await["publicKey"]["challenge"]
        .as_str()
        .expect("replacement challenge")
        .to_owned();
    assert_ne!(replacement_challenge, first_challenge);
    let replacement_payload: String = connection
        .get(pending_key)
        .await
        .expect("replacement passkey state");
    assert_ne!(replacement_payload, reserved_payload);
    let _: usize = connection
        .del(pending_key)
        .await
        .expect("cleanup passkey state");
}

/// 在一个 ticket 上耗尽 Passkey 注册失败额度，返回每次尝试的状态码。
pub(super) async fn exhaust_ticket_failures(
    router: &Router,
    ticket: &(String, String),
) -> Vec<StatusCode> {
    let response = post_with_cookie(
        router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut statuses = Vec::new();
    for _ in 0..ticket_failure_limit() {
        let response = post_with_cookie(
            router,
            "/api/v1/auth/passkeys/register/finish",
            serde_json::json!({
                "credential": bogus_registration_credential()
            }),
            &ticket.1,
        )
        .await;
        statuses.push(response.status());
    }
    statuses
}

pub(super) async fn mfa_failure_reasons(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
) -> Vec<(String, String)> {
    chenxing_auth::sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT actor_type, metadata->>'reason' FROM audit_events
         WHERE action = 'mfa_failure' AND actor_user_id = $1
         ORDER BY id ASC",
    )
    .bind(user_id)
    .fetch_all(database)
    .await
    .expect("mfa_failure audit events")
    .into_iter()
    .map(|(actor_type, reason)| (actor_type, reason.unwrap_or_default()))
    .collect()
}

pub(super) async fn user_id_for_email(database: &chenxing_auth::sqlx::PgPool, email: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(database)
        .await
        .expect("user lookup")
}

pub(super) async fn cleanup_user(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(database)
        .await
        .expect("user cleanup");
}
