use axum::{
    Router,
    body::Body,
    extract::Query,
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};

use chenxing_auth::{
    api,
    audit::{AuditAction, AuditEvent},
    config::Config,
    oauth::providers::domain::{ClientAuthMethod, ProviderInput},
    state::AppState,
    users::ManagementActorCredential,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct BindingStartResponse {
    authorization_url: String,
}

async fn mock_authorize(Query(query): Query<AuthorizeQuery>) -> Redirect {
    Redirect::to(&format!(
        "{}?code=mock-code&state={}",
        query.redirect_uri, query.state
    ))
}

async fn mock_token() -> axum::Json<Value> {
    axum::Json(serde_json::json!({"access_token":"mock-token", "token_type":"Bearer"}))
}

async fn mock_userinfo() -> axum::Json<Value> {
    axum::Json(serde_json::json!({
        "sub": "binding-subject",
        "email": "binding@example.test",
        "name": "Binding User",
        "email_verified": true
    }))
}

async fn mock_server() -> SocketAddr {
    let router = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", axum::routing::post(mock_token))
        .route("/userinfo", get(mock_userinfo));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move { axum::serve(listener, router).await.expect("mock server") });
    address
}

async fn setup(
    _mock: SocketAddr,
) -> (
    axum::Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("external_identity_repository", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-external-identity-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
    config.oauth_provider_loopback_enabled = true;
    config.oauth_provider_loopback_enabled = true;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    let router = api::router(state.clone());
    (router, state, database, key_directory)
}

async fn user_id(database: &chenxing_auth::sqlx::PgPool, username: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(database)
        .await
        .expect("user id")
}

async fn create_user(database: &chenxing_auth::sqlx::PgPool, suffix: &str) -> i64 {
    let username = format!("identity-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $2, 'not-used', NOW(), NOW())",
    )
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .execute(database)
    .await
    .expect("insert user");
    user_id(database, &username).await
}

async fn create_provider(state: &AppState, suffix: &str, mock: SocketAddr) -> i64 {
    let slug = format!("provider-{suffix}");
    let provider = state
        .external_oauth
        .create_with_audit(
            ProviderInput {
                name: format!("Provider {suffix}"),
                slug: slug.clone(),
                authorization_endpoint: format!("http://{mock}/authorize"),
                token_endpoint: format!("http://{mock}/token"),
                userinfo_endpoint: format!("http://{mock}/userinfo"),
                client_id: "client".to_owned(),
                client_secret: Some("mock-secret".to_owned()),
                scopes: vec!["openid".to_owned(), "email".to_owned()],
                subject_claim: "sub".to_owned(),
                email_claim: "email".to_owned(),
                name_claim: Some("name".to_owned()),
                email_verified_claim: Some("email_verified".to_owned()),
                client_auth_method: ClientAuthMethod::RequestBody,
                pkce_enabled: true,
            },
            ManagementActorCredential::SystemToken,
            AuditEvent::new(
                "system_token".to_owned(),
                None,
                AuditAction::OauthProviderCreate,
                "oauth_provider".to_owned(),
                Some(slug.clone()),
                serde_json::json!({"test": "external_identity_binding"}),
            ),
        )
        .await
        .expect("create provider");
    state
        .external_oauth
        .set_status_with_audit(
            &slug,
            "active",
            provider.state_version,
            ManagementActorCredential::SystemToken,
            AuditEvent::new(
                "system_token".to_owned(),
                None,
                AuditAction::OauthProviderActive,
                "oauth_provider".to_owned(),
                Some(slug.clone()),
                serde_json::json!({"test": "external_identity_binding"}),
            ),
        )
        .await
        .expect("enable provider");
    provider.id
}

fn cookie_pair(response: &axum::response::Response, prefix: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let pair = value.split(';').next()?;
            pair.starts_with(prefix).then_some(pair.to_owned())
        })
        .expect("cookie")
}

fn clears_cookie(response: &axum::response::Response, cookie_pair: &str) -> bool {
    let name = cookie_pair
        .split_once('=')
        .map(|(name, _)| name)
        .expect("cookie name");
    let cleared_prefix = format!("{name}=;");
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.starts_with(&cleared_prefix))
        })
}

async fn binding_fixture(
    router: &axum::Router,
    state: &AppState,
    database: &chenxing_auth::sqlx::PgPool,
    suffix: &str,
    mock: SocketAddr,
) -> (String, String, String, String, i64) {
    let user = create_user(database, suffix).await;
    let provider_id = create_provider(state, suffix, mock).await;
    let slug = format!("provider-{suffix}");
    let mut session = chenxing_auth::sessions::domain::Session::new(
        user.to_string(),
        std::time::Duration::from_secs(3600),
    )
    .expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save session");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/external-identities/{slug}/bind"))
                .header(
                    "cookie",
                    format!(
                        "chenxing_session={}; chenxing_csrf={}",
                        session.token, session.csrf_token
                    ),
                )
                .header("x-csrf-token", &session.csrf_token)
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let state_cookie = cookie_pair(&response, "chenxing_external_oauth_state_");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("binding start response body");
    let authorization_url = serde_json::from_slice::<BindingStartResponse>(&body)
        .expect("binding start response JSON")
        .authorization_url;
    let state_value = url::Url::parse(&authorization_url)
        .expect("authorization URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    (
        slug,
        state_cookie,
        state_value,
        format!(
            "chenxing_session={}; chenxing_csrf={}",
            session.token, session.csrf_token
        ),
        provider_id,
    )
}
fn external(subject: &str, email: &str) -> chenxing_auth::oauth::providers::claims::ExternalUser {
    chenxing_auth::oauth::providers::claims::ExternalUser {
        subject: subject.to_owned(),
        email: chenxing_auth::users::email::EmailAddress::parse(email).expect("email"),
        name: None,
        email_verified: true,
    }
}

#[tokio::test]
async fn binding_callback_rejects_bad_cookie_and_preserves_slug_mismatch_state() {
    let mock = mock_server().await;
    let (router, state, database, key_directory) = setup(mock).await;
    let (slug, state_cookie, state_value, session_cookie, _provider) =
        binding_fixture(&router, &state, &database, "http-state", mock).await;
    let state_cookie_name = state_cookie
        .split_once('=')
        .map(|(name, _)| name)
        .expect("binding state cookie name");

    let missing_cookie = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/bind/callback?code=mock-code&state={state_value}"
                ))
                .header("cookie", &session_cookie)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_cookie.status(), StatusCode::BAD_REQUEST);

    let mismatch_cookie = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/bind/callback?code=mock-code&state={state_value}"
                ))
                .header(
                    "cookie",
                    format!("{session_cookie}; chenxing_external_oauth_state_x=wrong"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(mismatch_cookie.status(), StatusCode::BAD_REQUEST);

    let other_slug = "provider-other";
    create_provider(&state, "other", mock).await;
    let wrong_provider = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{other_slug}/bind/callback?code=mock-code&state={state_value}"
                ))
                .header("cookie", format!("{session_cookie}; {state_cookie}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(wrong_provider.status(), StatusCode::BAD_REQUEST);
    assert!(
        !clears_cookie(&wrong_provider, &state_cookie),
        "a mismatched provider slug must leave the correct provider's state cookie intact"
    );

    let success = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/bind/callback?code=mock-code&state={state_value}"
                ))
                .header("cookie", format!("{session_cookie}; {state_cookie}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(success.status(), StatusCode::SEE_OTHER);

    let replay = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/bind/callback?code=mock-code&state={state_value}"
                ))
                .header("cookie", format!("{session_cookie}; {state_cookie}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(
        replay
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.starts_with(&format!("{state_cookie_name}="))
                && value.contains("Max-Age=0")),
        "a replayed binding callback must clear its stale state cookie"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
#[tokio::test]
async fn repository_binds_lists_and_rejects_replay_or_foreign_subject() {
    let mock = mock_server().await;
    let (_router, state, database, key_directory) = setup(mock).await;
    let first_user = create_user(&database, "first").await;
    let second_user = create_user(&database, "second").await;
    let provider = create_provider(&state, "one", mock).await;
    let identity = external("subject-1", "identity@example.test");

    chenxing_auth::oauth::providers::repository::bind_identity(
        &database, first_user, 0, provider, &identity,
    )
    .await
    .expect("first binding");
    let listed =
        chenxing_auth::oauth::providers::repository::list_identities(&database, first_user)
            .await
            .expect("list identities");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].subject, "subject-1");

    let replay = chenxing_auth::oauth::providers::repository::bind_identity(
        &database, first_user, 0, provider, &identity,
    )
    .await;
    assert!(matches!(
        replay,
        Err(chenxing_auth::oauth::providers::repository::BindIdentityError::AlreadyOwned)
    ));
    let foreign = chenxing_auth::oauth::providers::repository::bind_identity(
        &database,
        second_user,
        0,
        provider,
        &identity,
    )
    .await;
    assert!(matches!(
        foreign,
        Err(chenxing_auth::oauth::providers::repository::BindIdentityError::OwnedByAnotherUser)
    ));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn repository_rejects_stale_session_epoch_without_linking() {
    let mock = mock_server().await;
    let (_router, state, database, key_directory) = setup(mock).await;
    let user = create_user(&database, "epoch").await;
    let provider = create_provider(&state, "epoch", mock).await;
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 1 WHERE id = $1")
        .bind(user)
        .execute(&database)
        .await
        .expect("advance epoch");

    let result = chenxing_auth::oauth::providers::repository::bind_identity(
        &database,
        user,
        0,
        provider,
        &external("subject-epoch", "epoch@example.test"),
    )
    .await;
    assert!(matches!(
        result,
        Err(chenxing_auth::oauth::providers::repository::BindIdentityError::AuthenticationChanged)
    ));
    let count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(count, 0);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn linked_identity_list_requires_an_authenticated_session() {
    let (router, _state, _database, key_directory) =
        setup("127.0.0.1:1".parse().expect("address")).await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/external-identities")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}
