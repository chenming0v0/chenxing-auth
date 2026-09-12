use axum::http::StatusCode;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::http;

use super::passkey_auth::{
    ExistingChallengeBehavior, assert_start_reserves_one_challenge,
    bogus_authentication_credential, cleanup_user, create_user, insert_test_passkey, login_ticket,
    mfa_failure_reasons, post_with_cookie, rotate_issuer_generation, setup, user_id_for_email,
};

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
    let body = http::json_body(response).await;
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
        http::json_body(response).await["code"],
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
        http::json_body(response).await["code"],
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
    let body = http::json_body(response).await;
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
    let body = http::json_body(response).await;
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
