use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use redis::AsyncCommands;
use serde_json::Value;
use totp_rs::{Secret, TOTP};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
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
    let key_directory = std::env::temp_dir().join(format!("chenxing-oauth-ui-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "oauth-ui-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("state")),
        database,
        key_directory,
    )
}

async fn body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("UTF-8")
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_str(&body(response).await).expect("JSON")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location")
        .to_owned()
}

fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie")
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn request_id(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("request URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id")
}

fn html_value(body: &str, name: &str) -> String {
    body.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .and_then(|value| value.split('"').next())
        .expect("HTML form value")
        .to_owned()
}

fn html_data_attribute(body: &str, name: &str) -> String {
    body.split(&format!("data-{name}=\""))
        .nth(1)
        .and_then(|value| value.split('"').next())
        .expect("HTML data attribute")
        .to_owned()
}

#[tokio::test]
async fn logged_in_user_can_inspect_and_consume_oauth_ui_request_once() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("oauth-ui-{suffix}@example.com");
    let username = format!("oauth-ui-{suffix}");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "email": email, "password": password})
                        .to_string(),
                ))
                .expect("register request"),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer oauth-ui-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "OAuth UI Client",
                        "redirect_uris": ["https://oauth-ui.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    let client = json(response).await;
    let client_id = client["client_id"].as_str().expect("client id");
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Foauth-ui.example%2Fcallback&response_type=code&scope=openid%20profile&state=oauth-ui-state&nonce=oauth-ui-nonce&code_challenge=oauth-ui-challenge&code_challenge_method=S256"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    let login_location = location(&response);
    let request_id = request_id(&login_location);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "request_id={request_id}&email={email}&password={password}"
                )))
                .expect("browser login request"),
        )
        .await
        .expect("browser login response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup_body = body(response).await;
    let ticket = html_value(&setup_body, "login_ticket");
    assert!(setup_body.contains("<svg"));
    assert!(setup_body.contains("无法扫描"));
    assert!(!setup_body.contains("otpauth://"));
    let secret = html_data_attribute(&setup_body, "totp-secret");
    let totp = TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret).to_bytes().expect("TOTP secret"),
        None,
        String::new(),
    )
    .expect("TOTP");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/totp")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "request_id={request_id}&login_ticket={ticket}&code={}",
                    totp.generate_current().expect("TOTP code")
                )))
                .expect("browser TOTP request"),
        )
        .await
        .expect("browser TOTP response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let session_cookies = cookies(&response);
    assert!(location(&response).contains("/oauth/authorize/consent"));
    let csrf = session_cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("inspect request"),
        )
        .await
        .expect("inspect response");
    assert_eq!(response.status(), StatusCode::OK);
    let pending = json(response).await;
    assert_eq!(pending["client_name"], "OAuth UI Client");
    assert_eq!(pending["scopes"], serde_json::json!(["openid", "profile"]));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"invalid"}"#))
                .expect("invalid decision request"),
        )
        .await
        .expect("invalid decision response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("pending request after invalid decision"),
        )
        .await
        .expect("pending response after invalid decision");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve request"),
        )
        .await
        .expect("approve response");
    assert_eq!(response.status(), StatusCode::OK);
    let approved = json(response).await;
    assert!(
        approved["redirect_to"]
            .as_str()
            .is_some_and(|value| value.contains("code="))
    );
    assert!(
        approved["redirect_to"]
            .as_str()
            .is_some_and(|value| value.contains("state=oauth-ui-state"))
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("repeat inspect request"),
        )
        .await
        .expect("repeat inspect response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut redis_connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let quota_keys: Vec<String> = redis_connection
        .keys(format!("chenxing:oauth:quota:{client_id}:*"))
        .await
        .expect("quota keys");
    assert!(
        quota_keys.is_empty(),
        "administrator OAuth clients are unlimited"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
