use axum::{
    body::Body,
    http::{Request, StatusCode, header::LOCATION},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::sessions::domain::Session;
use chenxing_auth::{
    api,
    oauth::{code::AuthorizationCode, refresh::RefreshToken},
    state::AppState,
};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[path = "support/oauth_flow.rs"]
mod support;

use support::{
    create_test_client, disable_user, ensure_owner_bootstrapped, json_body, register_test_user,
    session_cookie, test_state,
};

#[tokio::test]
async fn disabled_user_session_cannot_authorize_or_submit_consent() {
    let (state, database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, _client_secret) = create_test_client(&router, "flow-admin-token").await;
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = session_cookie(&session);
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&response_type=code&scope=openid%20profile&state=disabled-state&nonce=disabled-nonce&code_challenge=disabled-challenge&code_challenge_method=S256"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("consent location")
        .to_owned();
    assert!(consent_location.starts_with("/oauth/consent?request_id="));
    let request_id = Url::parse(&format!("http://localhost{consent_location}"))
        .expect("consent URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id");

    disable_user(&database, user_id).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("disabled authorize request"),
        )
        .await
        .expect("disabled authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("/login?request_id="))
    );

    // A disabled user's session can no longer inspect the pending request over JSON.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("disabled inspect request"),
        )
        .await
        .expect("disabled inspect response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Nor submit a JSON consent decision.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"decision": "approve"}).to_string(),
                ))
                .expect("disabled consent request"),
        )
        .await
        .expect("disabled consent response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn disabled_user_cannot_exchange_oauth_credentials_without_consuming_them() {
    let (state, database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://disabled.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        challenge,
        Some("disabled-nonce".to_owned()),
    );
    let refresh = RefreshToken::new_with_nonce(
        client_id.clone(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        Some("disabled-nonce".to_owned()),
    );
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    state
        .refresh_tokens
        .save(&refresh)
        .await
        .expect("save refresh token");
    disable_user(&database, user_id).await;
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("code exchange request"),
        )
        .await
        .expect("code exchange response");
    assert_ne!(response.status(), StatusCode::OK);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find authorization code")
            .is_some(),
        "disabled-user rejection must not consume the authorization code"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("refresh request"),
        )
        .await
        .expect("refresh response");
    assert_ne!(response.status(), StatusCode::OK);
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find refresh token")
            .is_some(),
        "disabled-user rejection must not consume the refresh token"
    );

    let response = chenxing_auth::oauth::response::issue_token_response(
        &state,
        &user_id.to_string(),
        &client_id,
        &["openid".to_owned(), "profile".to_owned()],
        None,
        Some("disabled-nonce"),
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn refresh_token_remains_reusable_when_access_token_issuance_fails() {
    let (mut state, database, key_directory) = test_state().await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    let refresh = RefreshToken::new(
        client_id.clone(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
    );
    state
        .refresh_tokens
        .save(&refresh)
        .await
        .expect("save refresh token");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    state.config.session_ttl_seconds = u64::MAX;
    let failing_router = api::router(state.clone());
    let response = failing_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("failed refresh request"),
        )
        .await
        .expect("failed refresh response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find refresh after issuance failure")
            .is_some(),
        "failed token issuance must not consume the refresh token"
    );

    state.config.session_ttl_seconds = 3600;
    let retry_router = api::router(state.clone());
    let response = retry_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("retry refresh request"),
        )
        .await
        .expect("retry refresh response");
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response).await;
    let next_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find consumed refresh after retry")
            .is_none()
    );
    assert!(
        state
            .refresh_tokens
            .find(&next_refresh)
            .await
            .expect("find rotated refresh after retry")
            .is_some()
    );

    let response = retry_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("duplicate refresh request"),
        )
        .await
        .expect("duplicate refresh response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let duplicate = json_body(response).await;
    assert_eq!(duplicate["error"].as_str(), Some("invalid_grant"));

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
async fn refresh_token_count_for_client(state: &AppState, client_id: &str) -> usize {
    let mut connection = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("chenxing:oauth:refresh:*")
        .query_async(&mut connection)
        .await
        .expect("refresh token keys");
    let mut count = 0;
    for key in keys {
        let payload: Option<String> = connection.get(key).await.expect("refresh token payload");
        if payload
            .as_deref()
            .and_then(|value| serde_json::from_str::<RefreshToken>(value).ok())
            .is_some_and(|refresh| refresh.client_id == client_id)
        {
            count += 1;
        }
    }
    count
}

#[tokio::test]
async fn authorization_code_is_restored_when_token_issuance_fails() {
    let (mut state, database, key_directory) = test_state().await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://restore.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        challenge,
        Some("restore-nonce".to_owned()),
    );
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    state.config.session_ttl_seconds = u64::MAX;
    let failing_router = api::router(state.clone());
    let response = failing_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Frestore.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("failed code exchange request"),
        )
        .await
        .expect("failed code exchange response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find restored authorization code")
            .is_some(),
        "token issuance failure must restore the consumed authorization code"
    );
    assert_eq!(
        refresh_token_count_for_client(&state, &client_id).await,
        0,
        "token issuance failure must not leave an orphan refresh token"
    );

    state.config.session_ttl_seconds = 3600;
    let retry_router = api::router(state.clone());
    let response = retry_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Frestore.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("retry code exchange request"),
        )
        .await
        .expect("retry code exchange response");
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response).await;
    assert!(token["access_token"].as_str().is_some());
    assert!(token["refresh_token"].as_str().is_some());
    assert_eq!(refresh_token_count_for_client(&state, &client_id).await, 1);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find consumed authorization code")
            .is_none(),
        "successfully retried authorization code must remain consumed"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
