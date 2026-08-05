use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    api, config::Config, db, sessions::cookies::EXTERNAL_STATE_COOKIE_PREFIX, state::AppState,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/oauth_provider_concurrency.rs"]
mod oauth_provider_concurrency;

#[derive(Clone, Default)]
struct MockState {
    subject: String,
    token_form: Arc<Mutex<Option<HashMap<String, String>>>>,
    user_email: Arc<Mutex<String>>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
}

async fn mock_authorize(Query(query): Query<AuthorizeQuery>) -> Redirect {
    Redirect::to(&format!(
        "{}?code=mock-code&state={}",
        query.redirect_uri, query.state
    ))
}

async fn mock_token(
    State(state): State<MockState>,
    Form(form): Form<HashMap<String, String>>,
) -> axum::Json<Value> {
    *state.token_form.lock().await = Some(form);
    axum::Json(serde_json::json!({"access_token":"mock-access-token","token_type":"Bearer"}))
}

async fn mock_userinfo(State(state): State<MockState>) -> axum::Json<Value> {
    let email = state.user_email.lock().await.clone();
    axum::Json(serde_json::json!({
        "sub": state.subject,
        "email": email,
        "name": "External Person",
        "email_verified": true
    }))
}

async fn mock_server() -> (SocketAddr, MockState) {
    let email = format!("external-{}@example.com", Uuid::new_v4().simple());
    let state = MockState {
        subject: format!("mock-subject-{}", Uuid::new_v4().simple()),
        user_email: Arc::new(Mutex::new(email)),
        ..MockState::default()
    };
    let router = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", axum::routing::post(mock_token))
        .route("/userinfo", get(mock_userinfo))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("mock server");
    });
    (address, state)
}

async fn setup(
    mock: SocketAddr,
) -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL");
    db::migrate(&database).await.expect("migrations");
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-provider-flow-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "provider-flow-admin".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(AppState::new(config).await.expect("state"));
    let slug = format!("mock-{}", Uuid::new_v4().simple());
    let input = serde_json::json!({
        "name":"Mock Provider", "slug":slug,
        "authorization_endpoint":format!("http://{mock}/authorize"),
        "token_endpoint":format!("http://{mock}/token"),
        "userinfo_endpoint":format!("http://{mock}/userinfo"),
        "client_id":"mock-client", "client_secret":"mock-secret",
        "scopes":["openid","profile","email"], "subject_claim":"sub", "email_claim":"email",
        "name_claim":"name", "email_verified_claim":"email_verified", "client_auth_method":"request_body"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .expect("provider request"),
        )
        .await
        .expect("provider response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}/enable"))
                .header("authorization", "Bearer provider-flow-admin")
                .body(Body::empty())
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    (router, database, key_directory, slug)
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("location")
        .to_owned()
}

fn set_cookie(response: &axum::response::Response, name: &str) -> String {
    set_cookie_header(response, name)
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

fn set_cookie_header(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value.starts_with(name).then(|| value.to_owned())
        })
        .expect("cookie")
}

fn authorization_state(location: &str) -> String {
    url::Url::parse(location)
        .expect("authorization URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state")
}

#[tokio::test]
async fn custom_provider_registers_reuses_identity_and_rejects_state_replay() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_location = location(&response);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(&authorize_location)
        .send()
        .await
        .expect("mock authorize");
    assert_eq!(authorize_response.status(), reqwest::StatusCode::SEE_OTHER);
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("mock callback location")
        .to_owned();
    let callback = url::Url::parse(&callback_location).expect("callback URL");
    let state = callback
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&response).contains("external=success"),
        "unexpected callback location: {}",
        location(&response)
    );
    let first_session = set_cookie(&response, "chenxing_session=");
    let count: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(count.0, 1);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("second start"),
        )
        .await
        .expect("second start response");
    let second_state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let second_location = location(&response);
    let second_authorize = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(second_location)
        .send()
        .await
        .expect("second authorize");
    let second_callback = second_authorize
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("second callback location")
        .to_owned();
    let second_state = url::Url::parse(&second_callback)
        .expect("second callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("second state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("second callback request"),
        )
        .await
        .expect("second callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie(&response, "chenxing_session=") != first_session);
    let count: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("user count");
    assert_eq!(count.0, 1);
    let password_login_enabled: (bool,) =
        chenxing_auth::sqlx::query_as("SELECT password_login_enabled FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("external user password login flag");
    assert!(!password_login_enabled.0);

    let token_form = mock_state
        .token_form
        .lock()
        .await
        .clone()
        .expect("token form");
    let expected_form = HashMap::from([
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), "mock-code".to_owned()),
        (
            "redirect_uri".to_owned(),
            format!("http://127.0.0.1:3000/auth/external/{slug}/callback"),
        ),
        ("client_id".to_owned(), "mock-client".to_owned()),
        ("client_secret".to_owned(), "mock-secret".to_owned()),
    ]);
    assert_eq!(token_form, expected_form);

    let replay = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("replay request"),
        )
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert!(location(&replay).contains("external_error=oauth_login_failed"));
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn custom_provider_does_not_auto_link_existing_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let registration = serde_json::json!({
        "username": format!("local-{}", Uuid::new_v4().simple()),
        "email": external_email,
        "password": "local-password-123",
        "display_name": "Local Person"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(registration.to_string()))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(location(&response))
        .send()
        .await
        .expect("mock authorize");
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("callback location");
    let state = url::Url::parse(callback_location)
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).contains("external_error=oauth_account_link_required"));

    let identities: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(identities.0, 0);
    let _ = std::fs::remove_dir_all(key_directory);
}
