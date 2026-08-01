use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone, Default)]
struct MockState {
    subject: String,
    user_email: Arc<Mutex<String>>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
}

async fn mock_authorize(
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> Redirect {
    Redirect::to(&format!(
        "{}?code=mock-code&state={}",
        query.redirect_uri, query.state
    ))
}

async fn mock_token() -> axum::Json<Value> {
    axum::Json(serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer"
    }))
}

async fn mock_userinfo(
    axum::extract::State(state): axum::extract::State<MockState>,
) -> axum::Json<Value> {
    let email = state.user_email.lock().await.clone();
    axum::Json(serde_json::json!({
        "sub": state.subject,
        "email": email,
        "name": "External Person",
        "email_verified": true
    }))
}

async fn mock_server() -> SocketAddr {
    let state = MockState {
        subject: format!("mock-subject-{}", Uuid::new_v4().simple()),
        user_email: Arc::new(Mutex::new(format!(
            "external-{}@example.com",
            Uuid::new_v4().simple()
        ))),
    };
    let router = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", axum::routing::post(mock_token))
        .route("/userinfo", get(mock_userinfo))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("mock server");
    });
    address
}

async fn setup(
    mock: SocketAddr,
) -> (
    Router,
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
        std::env::temp_dir().join(format!("chenxing-provider-pending-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "provider-pending-admin".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(AppState::new(config).expect("state"));
    let slug = format!("mock-pending-{}", Uuid::new_v4().simple());
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
                .header("authorization", "Bearer provider-pending-admin")
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
                .header("authorization", "Bearer provider-pending-admin")
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
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let pair = value.split(';').next()?.to_owned();
            pair.starts_with(name).then_some(pair)
        })
        .expect("cookie")
}

async fn create_pending_request(router: &Router) -> (String, String) {
    let client_name = format!("Pending External Client {}", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer provider-pending-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": client_name,
                        "redirect_uris": ["https://pending.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("client body");
    let client: Value = serde_json::from_slice(&body).expect("client JSON");
    let client_id = client["client_id"].as_str().expect("client id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fpending.example%2Fcallback&response_type=code&scope=openid%20profile&state=pending-state&nonce=pending-nonce&code_challenge=pending-challenge&code_challenge_method=S256"
                ))
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = location(&response);
    let request_id = url::Url::parse(&format!("http://localhost{login_location}"))
        .expect("login URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id");
    (request_id, client_id.to_owned())
}

async fn begin_external_login(router: &Router, slug: &str, request_id: &str) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}?request_id={request_id}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&response, "chenxing_external_oauth_state_");
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(location(&response))
        .send()
        .await
        .expect("mock authorize");
    assert_eq!(authorize_response.status(), reqwest::StatusCode::SEE_OTHER);
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
    (state_cookie, state)
}

async fn complete_external_callback(
    router: &Router,
    slug: &str,
    state_cookie: &str,
    state: &str,
) -> axum::response::Response {
    router
        .clone()
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
        .expect("callback response")
}

#[tokio::test]
async fn external_callback_binds_pending_request_to_created_session() {
    let mock = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;
    let (client_request_id, client_id) = create_pending_request(&router).await;
    let (state_cookie, state) = begin_external_login(&router, &slug, &client_request_id).await;
    let response = complete_external_callback(&router, &slug, &state_cookie, &state).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("/oauth/consent?request_id={client_request_id}")
    );
    let session_cookie = set_cookie(&response, "chenxing_session=");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{client_request_id}"
                ))
                .header("cookie", session_cookie)
                .body(Body::empty())
                .expect("inspect request"),
        )
        .await
        .expect("inspect response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn external_callback_does_not_redirect_to_consent_when_pending_request_expires() {
    let mock = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;
    let (request_id, client_id) = create_pending_request(&router).await;
    let (state_cookie, state) = begin_external_login(&router, &slug, &request_id).await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut redis_connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = redis_connection
        .del(format!("chenxing:oauth:request:{request_id}"))
        .await
        .expect("delete pending request");

    let response = complete_external_callback(&router, &slug, &state_cookie, &state).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = location(&response);
    assert!(redirect.starts_with(&format!("/login?request_id={request_id}")));
    assert!(redirect.contains("external_error=oauth_request_expired"));
    assert!(!redirect.contains("/oauth/consent"));

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}
