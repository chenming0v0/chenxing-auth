use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    api,
    config::Config,
    db,
    oauth::{code::AuthorizationCode, refresh::RefreshToken},
    sessions::domain::Session,
    state::AppState,
};
use redis::AsyncCommands;
use serde_json::Value;
use sha2::{Digest, Sha256};
use totp_rs::TOTP;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

async fn test_state() -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for OAuth flow tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-flow-{}", Uuid::new_v4()));
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
    let state = AppState::new(config).expect("test state");
    (state, database, key_directory)
}

async fn test_router() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let (state, database, key_directory) = test_state().await;
    (api::router(state), database, key_directory)
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
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

fn cookie_header(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie value"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn session_cookie(session: &Session) -> String {
    format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    )
}

async fn register_test_user(router: &Router, suffix: &str) -> (i64, String, String, String) {
    let username = format!("disabled-{suffix}");
    let email = format!("disabled-{suffix}@example.com");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(status, StatusCode::CREATED, "registration response: {body}");
    let user_id = body["user"]["id"].as_i64().expect("numeric user id");
    (user_id, username, email, password.to_owned())
}

async fn ensure_owner_bootstrapped(router: &Router, suffix: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("test-owner-{suffix}"),
                        "email": format!("test-owner-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(
        matches!(
            response.status(),
            StatusCode::CREATED | StatusCode::CONFLICT
        ),
        "unexpected bootstrap response: {}",
        response.status()
    );
}

async fn create_test_client(router: &Router, token: &str) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Disabled User Client",
                        "redirect_uris": ["https://disabled.example/callback"],
                        "scopes": ["openid", "profile", "email"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client = json_body(response).await;
    (
        client["client_id"].as_str().expect("client id").to_owned(),
        client["client_secret"]
            .as_str()
            .expect("client secret")
            .to_owned(),
    )
}

async fn disable_user(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user_id)
        .execute(database)
        .await
        .expect("disable user");
}

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
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    assert_eq!(duplicate["code"].as_str(), Some("invalid_grant"));

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
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

#[tokio::test]
async fn owner_login_issues_shared_session_and_csrf_cookies() {
    let (state, database, key_directory) = test_state().await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let username = format!("oauth-owner-{suffix}");
    let email = format!("{username}@example.com");
    let password = "correct horse battery";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "role": "owner"
                    })
                    .to_string(),
                ))
                .expect("owner creation request"),
        )
        .await
        .expect("owner creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = json_body(response).await["id"].as_i64().expect("owner id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "identifier": username,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("owner login request"),
        )
        .await
        .expect("owner login response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let login_ticket = json_body(response).await["login_ticket"]
        .as_str()
        .expect("owner login ticket")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"login_ticket": login_ticket}).to_string(),
                ))
                .expect("owner TOTP setup request"),
        )
        .await
        .expect("owner TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let totp =
        TOTP::from_url(setup["otpauth_url"].as_str().expect("owner TOTP URI")).expect("owner TOTP");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "login_ticket": login_ticket,
                        "code": totp.generate_current().expect("owner TOTP code")
                    })
                    .to_string(),
                ))
                .expect("owner TOTP confirmation request"),
        )
        .await
        .expect("owner TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_header(&response);
    assert!(cookie.contains("chenxing_session="));
    assert!(cookie.contains("chenxing_csrf="));
    assert!(!cookie.contains("admin_session"));
    assert!(!cookie.contains("admin_csrf"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("owner cookie management request"),
        )
        .await
        .expect("owner cookie management response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(owner_id)
        .execute(&database)
        .await
        .expect("cleanup owner");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn browser_oauth_code_flow_reaches_userinfo_and_refresh() {
    let (router, database, key_directory) = test_router().await;
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let email = format!("flow-{suffix}@example.com");
    let username = format!("flow-{suffix}");
    let password = "correct horse battery";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "display_name": "Flow User"
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json_body(response).await;
    let user_id = user["user"]["id"].as_i64().expect("numeric user id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Flow Client",
                        "redirect_uris": ["https://flow.example/callback"],
                        "scopes": ["openid", "profile", "email"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client = json_body(response).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();

    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "token=unknown-token&token_type_hint=access_token",
                ))
                .expect("revocation request"),
        )
        .await
        .expect("revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let invalid_basic = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {invalid_basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=unknown-token"))
                .expect("invalid revocation request"),
        )
        .await
        .expect("invalid revocation response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token=unknown-token&client_id={client_id}&client_secret={client_secret}"
                )))
                .expect("form revocation request"),
        )
        .await
        .expect("form revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": username, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let ticket = json_body(response).await["login_ticket"]
        .as_str()
        .expect("login ticket")
        .to_owned();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"login_ticket": ticket}).to_string(),
                ))
                .expect("TOTP setup request"),
        )
        .await
        .expect("TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "login_ticket": ticket,
                        "code": totp.generate_current().expect("TOTP code")
                    })
                    .to_string(),
                ))
                .expect("TOTP confirmation request"),
        )
        .await
        .expect("TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookie = cookie_header(&response);
    assert!(session_cookie.contains("chenxing_session="));
    assert!(session_cookie.contains("chenxing_csrf="));

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorize_url =
        Url::parse("http://127.0.0.1:3000/oauth/authorize").expect("authorize URL");
    authorize_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://flow.example/callback")
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email")
        .append_pair("state", "flow-state")
        .append_pair("nonce", "flow-nonce")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_url.as_str())
                .header("cookie", &session_cookie)
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let redirect = Url::parse(location).expect("redirect URL");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value),
        Some("flow-state".into())
    );

    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fflow.example%2Fcallback&code_verifier={}",
        code, verifier,
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response).await;
    let access_token = token["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    assert!(token["id_token"].as_str().is_some());
    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("userinfo request"),
        )
        .await
        .expect("userinfo response");
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo = json_body(response).await;
    let user_id_text = user_id.to_string();
    assert_eq!(userinfo["sub"].as_str(), Some(user_id_text.as_str()));
    assert_eq!(userinfo["email"].as_str(), Some(email.as_str()));

    let refresh_form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        refresh_token, client_id, client_secret,
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(refresh_form.replace(
                    &format!("&client_id={client_id}&client_secret={client_secret}"),
                    "",
                )))
                .expect("refresh request"),
        )
        .await
        .expect("refresh response");
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response).await;
    assert!(refreshed["access_token"].as_str().is_some());
    assert!(refreshed["refresh_token"].as_str().is_some());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={access_token}")))
                .expect("access token revocation request"),
        )
        .await
        .expect("access token revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("revoked userinfo request"),
        )
        .await
        .expect("revoked userinfo response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let csrf = session_cookie
        .split(';')
        .find_map(|value| value.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned();
    let response = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .header("cookie", &session_cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("session revoke request"),
        )
        .await
        .expect("session revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);

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
