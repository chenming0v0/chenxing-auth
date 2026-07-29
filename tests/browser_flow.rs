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
        .expect("PostgreSQL is required for browser flow tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-browser-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "browser-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("test state")),
        database,
        key_directory,
    )
}

async fn body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body")
            .to_vec(),
    )
    .expect("UTF-8 response")
}

fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie header")
                .split(';')
                .next()
                .expect("cookie pair")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned()
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
async fn browser_login_and_consent_issue_authorization_code_and_reuse_consent() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("browser-owner-{suffix}"),
                        "email": format!("browser-owner-{suffix}@example.com"),
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(matches!(
        response.status(),
        StatusCode::CREATED | StatusCode::CONFLICT
    ));
    let email = format!("browser-{suffix}@example.com");
    let username = format!("browser-{suffix}");
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
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer browser-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Browser Client",
                        "redirect_uris": ["https://browser.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    let client: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("client JSON");
    let client_id = client["client_id"].as_str().expect("client id");

    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fbrowser.example%2Fcallback&response_type=code&scope=openid%20profile&state=browser-state&nonce=browser-nonce&code_challenge=browser-challenge&code_challenge_method=S256"
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = location(&response);
    assert!(login_location.starts_with("/auth/login?request_id="));
    let request_id = Url::parse(&format!("http://localhost{login_location}"))
        .expect("login URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "request_id={request_id}&identifier={username}&password={password}"
                )))
                .expect("browser login request"),
        )
        .await
        .expect("browser login response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup_body = body(response).await;
    let ticket = html_value(&setup_body, "login_ticket");
    assert!(
        setup_body.contains("<svg"),
        "setup page should contain a local QR SVG"
    );
    assert!(
        setup_body.contains("无法扫描"),
        "setup page should offer manual secret entry"
    );
    assert!(
        setup_body.contains("复制"),
        "setup page should offer a copy control"
    );
    assert!(
        !setup_body.contains("otpauth://"),
        "setup page must not print the complete otpauth URI"
    );
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
    let consent_location = location(&response);
    assert!(consent_location.starts_with("/oauth/authorize/consent?request_id="));
    let consent_id = Url::parse(&format!("http://localhost{consent_location}"))
        .expect("consent URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("consent request id");
    let csrf = session_cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&consent_location)
                .header("accept", "text/html")
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("consent page request"),
        )
        .await
        .expect("consent page response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body(response).await.contains("Browser Client"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/authorize/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", &session_cookies)
                .body(Body::from(format!(
                    "request_id={consent_id}&decision=approve&csrf_token={csrf}"
                )))
                .expect("consent decision request"),
        )
        .await
        .expect("consent decision response");
    let consent_status = response.status();
    let consent_location = location(&response);
    let consent_body = body(response).await;
    assert_eq!(
        consent_status,
        StatusCode::SEE_OTHER,
        "consent response: {consent_body}"
    );
    let first_code = Url::parse(&consent_location)
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");
    assert!(!first_code.is_empty());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("repeat authorize request"),
        )
        .await
        .expect("repeat authorize response");
    let repeat_status = response.status();
    let repeat_location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let repeat_body = body(response).await;
    assert_eq!(
        repeat_status,
        StatusCode::SEE_OTHER,
        "repeat response: {repeat_body}"
    );
    assert!(
        repeat_location
            .as_deref()
            .is_some_and(|value| value.contains("code="))
    );

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM user_consents WHERE user_id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("consent cleanup");
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("client cleanup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
