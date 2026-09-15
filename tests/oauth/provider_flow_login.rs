use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::auth_factors::store::LoginTicketStore;
use redis::AsyncCommands;
use tower::ServiceExt;
use uuid::Uuid;

use crate::http;

use super::provider_flow::{
    mock_server, run_external_login, run_external_login_with_cookies, set_cookie,
    set_cookie_header, set_cookie_header_optional, setup,
};

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

fn cookie_pair_value(cookie: &str, name: &str) -> String {
    cookie
        .split("; ")
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .expect("cookie value")
        .to_owned()
}

fn assert_expired_login_ticket_cookies(response: &axum::response::Response) {
    let ticket = set_cookie_header(response, "chenxing_login_ticket=");
    let holder = set_cookie_header(response, "chenxing_login_holder=");
    assert!(
        ticket.contains("Max-Age=0"),
        "login ticket cookie must be cleared: {ticket}"
    );
    assert!(
        holder.contains("Max-Age=0"),
        "login holder cookie must be cleared: {holder}"
    );
}

async fn login_ticket_exists(ticket_id: &str) -> bool {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let client = redis::Client::open(redis_url).expect("Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    connection
        .exists(LoginTicketStore::key(ticket_id))
        .await
        .expect("ticket exists")
}

async fn create_local_password_user(router: &axum::Router) -> (String, String, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("local-{suffix}");
    let email = format!("local-{suffix}@example.com");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer provider-flow-admin")
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
    (username, email, password.to_owned())
}

async fn password_pending_cookies(router: &axum::Router, username: &str, password: &str) -> String {
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
    pending_cookie(&response)
}

/// #465：同一浏览器先本地密码进入 MFA，再外部 OAuth 成功时必须清掉旧 ticket。
#[tokio::test]
async fn external_login_clears_leftover_password_mfa_ticket() {
    let (mock, mock_state) = mock_server().await;
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let (local_username, local_email, password) = create_local_password_user(&router).await;
    // 当前登录契约：未配置任何因子时密码直接完成登录（200），不产生待定
    // ticket。本用例验证「旧 MFA ticket 被外部登录清除」，先种一个 TOTP
    // 因子让密码登录进入 202 factor_required。
    let user_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(&local_username)
            .fetch_one(&database)
            .await
            .expect("load local user id");
    chenxing_auth::auth_factors::repository::insert_totp_factor_if_empty(
        &database,
        user_id,
        0,
        &[1, 2, 3],
    )
    .await
    .expect("seed TOTP factor");
    let pending = password_pending_cookies(&router, &local_username, &password).await;
    let ticket_id = cookie_pair_value(&pending, "chenxing_login_ticket");
    assert!(
        login_ticket_exists(&ticket_id).await,
        "password login must persist a Redis ticket before external OAuth"
    );

    let response = run_external_login_with_cookies(&router, &slug, Some(&pending)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&response).contains("external=success"),
        "unexpected callback location: {}",
        http::location(&response)
    );
    assert_expired_login_ticket_cookies(&response);
    assert!(
        !login_ticket_exists(&ticket_id).await,
        "leftover Redis ticket must be deleted or no longer consumable"
    );

    let session_cookie = set_cookie(&response, "chenxing_session=");
    let me = http::json_body(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .header("cookie", &session_cookie)
                    .body(Body::empty())
                    .expect("me request"),
            )
            .await
            .expect("me response"),
    )
    .await;
    assert_eq!(me["email"], external_email);
    assert_ne!(me["email"], local_email);

    let leftover = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup")
                .header("content-type", "application/json")
                .header("cookie", &pending)
                .body(Body::from("{}"))
                .expect("totp setup request"),
        )
        .await
        .expect("totp setup response");
    assert_eq!(leftover.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(leftover).await["code"],
        "invalid_login_ticket"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

/// #465：没有旧 ticket 时外部登录仍成功，并且同样下发过期的 ticket/holder Cookie。
#[tokio::test]
async fn external_login_without_old_ticket_still_clears_pending_cookies() {
    let (mock, _mock_state) = mock_server().await;
    let (router, _database, key_directory, slug) = setup(mock).await;
    let response = run_external_login(&router, &slug).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(http::location(&response).contains("external=success"));
    assert_expired_login_ticket_cookies(&response);
    assert!(set_cookie_header_optional(&response, "chenxing_session=").is_some());
    let _ = std::fs::remove_dir_all(key_directory);
}
