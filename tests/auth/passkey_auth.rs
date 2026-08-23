use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine;
use chenxing_auth::auth_limiter::FailureDimension;
use chenxing_auth::{
    api, auth_factors::domain::FactorMethod, config::Config, sessions::cookies, state::AppState,
    users::domain::AuthenticatedUser,
};
use redis::AsyncCommands;
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{db_isolation, oauth_flow};

async fn setup() -> (
    Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("passkey_auth", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-passkey-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "flow-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let email = format!("passkey-{}@example.com", Uuid::new_v4().simple());
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "passkey_auth", "passkey_auth").await;
    (router, state, database, key_directory, email)
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn post_with_cookie(
    router: &Router,
    uri: &str,
    body: serde_json::Value,
    cookie: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

/// 逐个 ticket 的 Passkey 失败上限直接取自限流域模型，避免测试与实现漂移。
fn ticket_failure_limit() -> usize {
    FailureDimension::Ticket.limit() as usize
}

fn bogus_registration_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "",
        "rawId": "",
        "response": {"attestationObject": "", "clientDataJSON": ""},
        "type": "public-key"
    })
}

fn bogus_authentication_credential() -> serde_json::Value {
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

fn rotate_issuer_generation(state: &AppState) {
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

async fn insert_test_passkey(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
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

async fn create_user(router: &Router, email: &str) -> String {
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

async fn login_ticket(
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
enum ExistingChallengeBehavior {
    Reject,
    Reuse,
}

/// #337：同一个 ticket 的 start 只能原子预留一份 challenge/state。
///
/// 注册 start 的并发败者和后续重复请求都必须明确拒绝；认证 start 则允许浏览器
/// 在取消 ceremony 后重试，但只能复用原 challenge。两条路径都不能改写胜者状态。
/// 删除 pending 后仍能用同一 ticket 重新 start，证明拒绝或幂等重试没有消耗或悬挂
/// 失败额度。
async fn assert_start_reserves_one_challenge(
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
    let winner_body = json_response(winner).await;
    let first_challenge = winner_body["publicKey"]["challenge"]
        .as_str()
        .expect("winner challenge")
        .to_owned();
    match existing_behavior {
        ExistingChallengeBehavior::Reject => assert_eq!(
            json_response(other).await["code"],
            "invalid_login_ticket",
            "the concurrent loser must be explicitly rejected"
        ),
        ExistingChallengeBehavior::Reuse => assert_eq!(
            json_response(other).await["publicKey"]["challenge"],
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
                    json_response(response).await["code"],
                    "invalid_login_ticket"
                );
            }
            ExistingChallengeBehavior::Reuse => {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    json_response(response).await["publicKey"]["challenge"],
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
    let replacement_challenge = json_response(response).await["publicKey"]["challenge"]
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
async fn exhaust_ticket_failures(router: &Router, ticket: &(String, String)) -> Vec<StatusCode> {
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

async fn mfa_failure_reasons(
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

async fn user_id_for_email(database: &chenxing_auth::sqlx::PgPool, email: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(database)
        .await
        .expect("user lookup")
}

async fn cleanup_user(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(database)
        .await
        .expect("user cleanup");
}

#[tokio::test]
async fn passkey_registration_start_returns_creation_challenge_for_login_ticket() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert!(body["publicKey"]["challenge"].as_str().is_some());
    assert!(body["publicKey"]["rp"]["id"].as_str().is_some());
    assert_eq!(
        body["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    assert!(body["session_id"].is_null());

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": {
                "id": "",
                "rawId": "",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "type": "public-key"
            }
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn discoverable_passkey_start_returns_a_usernameless_challenge() {
    let (router, _state, _database, key_directory, _email) = setup().await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/discoverable/start",
        serde_json::json!({}),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert!(Uuid::parse_str(body["challenge_id"].as_str().expect("challenge id")).is_ok());
    assert!(body["options"]["publicKey"]["challenge"].as_str().is_some());
    assert_eq!(body["options"]["publicKey"]["userVerification"], "required");
    assert!(
        body["options"]["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_authentication_binds_challenge_to_issuer_generation() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    insert_test_passkey(&database, user_id).await;
    let ticket = login_ticket(&state, &database, &email).await;
    let pending_key = format!("chenxing:auth:passkey-authentication:{}", ticket.0);

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(&pending_key)
            .await
            .expect("authentication snapshot"),
    )
    .expect("authentication snapshot JSON");
    assert_eq!(pending["issuer_generation"], 1);

    rotate_issuer_generation(&state);
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/finish",
        serde_json::json!({
            "credential": bogus_authentication_credential()
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_response(response).await["code"],
        "invalid_login_ticket"
    );

    let remaining: Option<String> = connection.get(&pending_key).await.expect("stale cleanup");
    assert!(
        remaining.is_none(),
        "stale authentication payload must be deleted"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn legacy_passkey_authentication_payload_is_deleted_before_verification() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    insert_test_passkey(&database, user_id).await;
    let ticket = login_ticket(&state, &database, &email).await;
    let pending_key = format!("chenxing:auth:passkey-authentication:{}", ticket.0);

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let mut pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(&pending_key)
            .await
            .expect("authentication snapshot"),
    )
    .expect("authentication snapshot JSON");
    pending
        .as_object_mut()
        .expect("authentication snapshot object")
        .remove("issuer_generation");
    let _: () = connection
        .set(&pending_key, pending.to_string())
        .await
        .expect("write legacy authentication snapshot");

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/finish",
        serde_json::json!({
            "credential": bogus_authentication_credential()
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_response(response).await["code"],
        "invalid_login_ticket"
    );

    let remaining: Option<String> = connection.get(&pending_key).await.expect("legacy cleanup");
    assert!(
        remaining.is_none(),
        "legacy authentication payload must be deleted"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn discoverable_passkey_authentication_binds_challenge_to_issuer_generation() {
    let (router, state, _database, key_directory, _email) = setup().await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/discoverable/start",
        serde_json::json!({}),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    let challenge_id = body["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();
    let pending_key = format!("chenxing:auth:passkey-discoverable:{challenge_id}");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(&pending_key)
            .await
            .expect("discoverable authentication snapshot"),
    )
    .expect("discoverable authentication snapshot JSON");
    assert_eq!(pending["issuer_generation"], 1);

    rotate_issuer_generation(&state);
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/discoverable/finish",
        serde_json::json!({
            "challenge_id": challenge_id,
            "credential": bogus_authentication_credential()
        }),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let remaining: Option<String> = connection.get(&pending_key).await.expect("stale cleanup");
    assert!(
        remaining.is_none(),
        "stale discoverable payload must be deleted"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn legacy_discoverable_passkey_payload_is_deleted_before_verification() {
    let (router, _state, _database, key_directory, _email) = setup().await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/discoverable/start",
        serde_json::json!({}),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    let challenge_id = body["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();
    let pending_key = format!("chenxing:auth:passkey-discoverable:{challenge_id}");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let mut pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(&pending_key)
            .await
            .expect("discoverable authentication snapshot"),
    )
    .expect("discoverable authentication snapshot JSON");
    pending
        .as_object_mut()
        .expect("discoverable authentication snapshot object")
        .remove("issuer_generation");
    let _: () = connection
        .set(&pending_key, pending.to_string())
        .await
        .expect("write legacy discoverable snapshot");

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/discoverable/finish",
        serde_json::json!({
            "challenge_id": challenge_id,
            "credential": bogus_authentication_credential()
        }),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let remaining: Option<String> = connection.get(&pending_key).await.expect("legacy cleanup");
    assert!(
        remaining.is_none(),
        "legacy discoverable payload must be deleted"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_registration_starts_reserve_one_challenge_without_burning_failures() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;
    let pending_key = format!("chenxing:auth:passkey-registration:{}", ticket.0);

    assert_start_reserves_one_challenge(
        &router,
        "/api/v1/auth/passkeys/register/start",
        &ticket,
        &pending_key,
        ExistingChallengeBehavior::Reject,
    )
    .await;
    assert!(
        mfa_failure_reasons(&database, user_id).await.is_empty(),
        "rejected registration starts must not be recorded as failures"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_authentication_starts_reserve_one_challenge_without_burning_failures() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    insert_test_passkey(&database, user_id).await;
    let ticket = login_ticket(&state, &database, &email).await;
    let pending_key = format!("chenxing:auth:passkey-authentication:{}", ticket.0);

    assert_start_reserves_one_challenge(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        &ticket,
        &pending_key,
        ExistingChallengeBehavior::Reuse,
    )
    .await;
    assert!(
        mfa_failure_reasons(&database, user_id).await.is_empty(),
        "authentication start retries must not be recorded as failures"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_registration_uses_updated_settings_and_keeps_start_snapshot() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let old_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "Old RP",
        "rp_id": "example.com",
        "user_verification": "required",
        "authenticator_attachment": "platform",
        "allow_insecure_origin": false,
        "allowed_origins": ["https://login.example.com"]
    });
    chenxing_auth::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('passkey', $1, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(old_setting.to_string())
    .execute(&database)
    .await
    .expect("old passkey setting");

    let ticket = login_ticket(&state, &database, &email).await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "Old RP");
    assert_eq!(challenge["publicKey"]["rp"]["id"], "example.com");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );

    let new_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "New RP",
        "rp_id": "example.com",
        "user_verification": "preferred",
        "authenticator_attachment": "cross_platform",
        "allow_insecure_origin": true,
        "allowed_origins": ["http://new.example.com"]
    });
    chenxing_auth::sqlx::query(
        "UPDATE app_settings SET setting_value = $1, updated_at = NOW()
         WHERE setting_key = 'passkey'",
    )
    .bind(new_setting.to_string())
    .execute(&database)
    .await
    .expect("new passkey setting");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!("chenxing:auth:passkey-registration:{}", ticket.0))
            .await
            .expect("registration snapshot"),
    )
    .expect("registration snapshot JSON");
    assert_eq!(pending["settings"]["rp_name"], "Old RP");
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["https://login.example.com"])
    );

    let second_ticket = login_ticket(&state, &database, &email).await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &second_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "New RP");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "cross-platform"
    );
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!(
                "chenxing:auth:passkey-registration:{}",
                second_ticket.0
            ))
            .await
            .expect("updated registration snapshot"),
    )
    .expect("updated registration snapshot JSON");
    assert_eq!(pending["settings"]["allow_insecure_origin"], true);
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["http://new.example.com"])
    );

    chenxing_auth::sqlx::query("DELETE FROM app_settings WHERE setting_key = 'passkey'")
        .execute(&database)
        .await
        .expect("passkey setting cleanup");
    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _: usize = connection
        .del(format!("chenxing:auth:passkey-registration:{}", ticket.0))
        .await
        .expect("old snapshot cleanup");
    let _: usize = connection
        .del(format!(
            "chenxing:auth:passkey-registration:{}",
            second_ticket.0
        ))
        .await
        .expect("new snapshot cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_finish_failures_are_rate_limited_and_invalidate_the_ticket() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;

    // 阈值内的失败仍然按“凭据无效”处理，不会被限流提前拒绝。
    let statuses = exhaust_ticket_failures(&router, &ticket).await;
    assert!(
        statuses
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED),
        "expected every in-window failure to stay 401, got {statuses:?}"
    );

    // ticket 维度达阈值后 ticket 已被失效，后续请求连挂起状态都不复存在。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": bogus_registration_credential()
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_response(response).await["code"],
        "invalid_login_ticket"
    );

    // mfa_failure 审计事件必须带真实 actor_id，而不是写死的 anonymous。
    let events = mfa_failure_reasons(&database, user_id).await;
    assert_eq!(events.len(), ticket_failure_limit());
    assert!(
        events.iter().all(|(actor_type, _)| actor_type == "user"),
        "expected user actor_type on every mfa_failure event, got {events:?}"
    );
    let reasons: Vec<&str> = events.iter().map(|(_, reason)| reason.as_str()).collect();
    assert_eq!(
        reasons.last().copied(),
        Some("passkey_rate_limited"),
        "expected the threshold failure to be recorded as rate limited, got {reasons:?}"
    );
    assert!(
        reasons[..ticket_failure_limit() - 1]
            .iter()
            .all(|reason| *reason == "passkey_invalid"),
        "expected sub-threshold failures to stay passkey_invalid, got {reasons:?}"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_start_endpoints_reject_before_touching_passkey_storage() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;

    let other_email = format!("passkey-other-{}@example.com", Uuid::new_v4().simple());
    let _other_username = create_user(&router, &other_email).await;
    let other_user_id = user_id_for_email(&database, &other_email).await;

    // 账号维度上限高于单个 ticket 上限，需要多个 ticket 才能把账号额度耗尽。
    // spare_ticket 必须在耗尽之前签发：账号被限流后 /auth/login 自身也会被拒绝。
    let tickets_to_exhaust_account =
        (FailureDimension::Account.limit() as usize).div_ceil(ticket_failure_limit());
    let mut burn_tickets = Vec::new();
    for _ in 0..tickets_to_exhaust_account {
        burn_tickets.push(login_ticket(&state, &database, &email).await);
    }
    let spare_ticket = login_ticket(&state, &database, &email).await;
    let other_ticket = login_ticket(&state, &database, &other_email).await;

    for ticket in &burn_tickets {
        exhaust_ticket_failures(&router, ticket).await;
    }

    // 账号维度耗尽后，challenge 端点必须在 list_passkeys 之前就拒绝。该账号没有任何
    // Passkey，若限流检查在数据库查询之后才生效，这里会退化成 400 invalid_login_ticket。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_response(response).await["code"], "invalid_factor");

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 限流按账号隔离：另一个账号的成功路径不受这些失败影响。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &other_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        mfa_failure_reasons(&database, other_user_id)
            .await
            .is_empty(),
        "unrelated account must not accumulate mfa_failure events"
    );

    cleanup_user(&database, user_id).await;
    cleanup_user(&database, other_user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}
