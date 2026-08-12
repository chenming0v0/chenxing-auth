use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use totp_rs::{Secret, TOTP};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

const ADMIN_TOKEN: &str = "totp-admin-token";

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("totp_auth", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-totp-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let owner_suffix = Uuid::new_v4().simple().to_string();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    let router = api::router(state);
    let bootstrap = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("totp-owner-{owner_suffix}"),
                        "email": format!("totp-owner-{owner_suffix}@example.com"),
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(matches!(
        bootstrap.status(),
        StatusCode::CREATED | StatusCode::CONFLICT
    ));
    let email = format!("totp-{}@example.com", Uuid::new_v4().simple());
    (router, database, key_directory, email)
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn request(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

async fn create_user(router: &Router, username: &str, email: &str, password: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
}

fn pending_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn request_with_cookie(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
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
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

#[tokio::test]
async fn password_login_without_factor_returns_pending_setup_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

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
    let cookie = pending_cookie(&response);
    let body = json_body(response).await;
    assert_eq!(body["status"], "factor_setup_required");
    assert!(body.get("login_ticket").is_none());
    assert!(cookie.contains("chenxing_login_ticket="));
    assert!(cookie.contains("chenxing_login_holder="));
    assert_eq!(body["methods"][0], "totp");

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
async fn totp_login_endpoint_completes_a_pending_factor_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-login-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let cookie = pending_cookie(&login_response);
    let _pending = json_body(login_response).await;
    let setup = json_body(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({}),
            &cookie,
        )
        .await,
    )
    .await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": totp.generate_current().expect("TOTP code")}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_some());

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn totp_login_ticket_is_invalidated_after_five_failed_codes() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-limit-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let cookie = pending_cookie(&login_response);
    let _pending = json_body(login_response).await;
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup",
        serde_json::json!({}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    for _ in 0..5 {
        let response = request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": "000000"}),
            &cookie,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn totp_setup_confirm_issues_session_and_consumes_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let cookie = pending_cookie(&response);
    let _pending = json_body(response).await;

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup",
        serde_json::json!({}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let secret = setup["secret_base32"].as_str().expect("TOTP secret");
    let uri = setup["otpauth_url"].as_str().expect("otpauth URI");
    assert!(uri.starts_with("otpauth://totp/"));
    let totp = TOTP::from_url(uri).expect("TOTP URI");
    assert_eq!(totp.get_secret_base32(), secret);
    // 注册用**上一个时间步**的码：注册确认现在也会 claim `user/timestep`（#301），
    // 而本用例末尾还要用当前步的码断言内联登录成功。用当前步注册会把那一步烧掉。
    // 上一步的码仍在 ±1 步接受窗口内。
    let code = totp.generate(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs()
            .saturating_sub(30),
    );

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"code": "000000"}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"code": code}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_some());
    let session_body = json_body(response).await;
    assert!(session_body["session_id"].is_null());

    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"code": code}),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(response).await["status"], "factor_required");
    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let second_cookie = pending_cookie(&login_response);
    let _pending = json_body(login_response).await;
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &second_cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password, "totp_code": "000000"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let secret_bytes = Secret::Encoded(secret.to_owned())
        .to_bytes()
        .expect("secret bytes");
    let valid_code = TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        String::new(),
    )
    .expect("TOTP");
    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({
            "identifier": email,
            "password": password,
            "totp_code": valid_code.generate_current().expect("valid code")
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

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
