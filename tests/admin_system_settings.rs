use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_system_settings", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-admin-system-settings-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-system-settings-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database.clone())
                .await
                .expect("state"),
        ),
        database,
        key_directory,
    )
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

#[tokio::test]
async fn owner_can_manage_passkey_email_policy_and_smtp_settings() {
    let (router, database, key_directory) = setup().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/passkey")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("passkey get"),
        )
        .await
        .expect("passkey get response");
    assert_eq!(response.status(), StatusCode::OK);
    let current = json(response).await;
    assert_eq!(current["enabled"], true);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/passkey")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "enabled": true,
                        "rp_name": "辰星认证中枢",
                        "rp_id": "localhost",
                        "user_verification": "preferred",
                        "authenticator_attachment": "any",
                        "allow_insecure_origin": true,
                        "allowed_origins": ["http://localhost:3000"]
                    })
                    .to_string(),
                ))
                .expect("passkey put"),
        )
        .await
        .expect("passkey put response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["rp_id"], "localhost");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/email-policy")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("email policy get"),
        )
        .await
        .expect("email policy get response");
    assert_eq!(response.status(), StatusCode::OK);
    let current_policy = json(response).await;
    let expected_generation = current_policy["generation"]
        .as_i64()
        .expect("email policy generation");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/email-policy")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "whitelist_enabled": true,
                        "alias_restriction_enabled": true,
                        "allowed_domains": ["example.com", "EXAMPLE.COM"],
                        "expected_generation": expected_generation
                    })
                    .to_string(),
                ))
                .expect("email policy put"),
        )
        .await
        .expect("email policy put response");
    assert_eq!(response.status(), StatusCode::OK);
    let policy = json(response).await;
    let expected_generation = policy["generation"]
        .as_i64()
        .expect("email policy generation after update");
    assert_eq!(
        policy["allowed_domains"],
        serde_json::json!(["example.com"])
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "host": "smtp.example.com",
                        "port": 587,
                        "username": "noreply@example.com",
                        "from_address": "辰星认证中枢 <noreply@example.com>",
                        "ssl_enabled": true,
                        "force_auth_login": false,
                        "password": "super-secret-smtp"
                    })
                    .to_string(),
                ))
                .expect("smtp put"),
        )
        .await
        .expect("smtp put response");
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = json(response).await;
    assert_eq!(smtp["password_configured"], true);
    assert!(smtp.get("password").is_none());
    assert!(smtp.get("password_ciphertext").is_none());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("smtp get"),
        )
        .await
        .expect("smtp get response");
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = json(response).await;
    assert_eq!(smtp["host"], "smtp.example.com");
    assert_eq!(smtp["password_configured"], true);
    assert!(smtp.get("password").is_none());

    // cleanup policy to avoid affecting other registration tests
    let _ = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/email-policy")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "whitelist_enabled": false,
                        "alias_restriction_enabled": false,
                        "allowed_domains": [],
                        "expected_generation": expected_generation
                    })
                    .to_string(),
                ))
                .expect("email policy reset"),
        )
        .await;
    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_can_manage_security_limits_with_validation() {
    let (router, database, key_directory) = setup().await;

    // 1. 读取默认值
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("security limits get"),
        )
        .await
        .expect("security limits get response");
    assert_eq!(response.status(), StatusCode::OK);
    let defaults = json(response).await;
    assert_eq!(defaults["unauthenticated_source_qps"], 30);
    assert_eq!(defaults["authorization_code_ttl_seconds"], 300);
    assert_eq!(defaults["ip_failure_limit"], 30);

    // 2. 合法更新后回读一致
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 10,
                        "authorization_code_ttl_seconds": 120,
                        "pending_request_ttl_seconds": 300,
                        "max_pending_requests_per_client": 15,
                        "max_pending_requests_global": 500,
                        "auth_failure_window_seconds": 600,
                        "account_failure_limit": 5,
                        "ip_failure_limit": 20,
                        "totp_ticket_failure_limit": 3,
                        "external_login_state_ttl_seconds": 300,
                        "external_login_state_rate_window_seconds": 30,
                        "external_login_state_rate_limit": 15,
                        "external_login_state_max_pending": 5000
                    })
                    .to_string(),
                ))
                .expect("security limits put"),
        )
        .await
        .expect("security limits put response");
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json(response).await;
    assert_eq!(updated["unauthenticated_source_qps"], 10);
    assert_eq!(updated["authorization_code_ttl_seconds"], 120);
    assert_eq!(updated["ip_failure_limit"], 20);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("security limits get after update"),
        )
        .await
        .expect("security limits get after update response");
    assert_eq!(response.status(), StatusCode::OK);
    let refetched = json(response).await;
    assert_eq!(refetched["unauthenticated_source_qps"], 10);
    assert_eq!(refetched["ip_failure_limit"], 20);

    // 3. 非法值（0）返回 400
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 0,
                        "authorization_code_ttl_seconds": 120,
                        "pending_request_ttl_seconds": 300,
                        "max_pending_requests_per_client": 15,
                        "max_pending_requests_global": 500,
                        "auth_failure_window_seconds": 600,
                        "account_failure_limit": 5,
                        "ip_failure_limit": 20,
                        "totp_ticket_failure_limit": 3,
                        "external_login_state_ttl_seconds": 300,
                        "external_login_state_rate_window_seconds": 30,
                        "external_login_state_rate_limit": 15,
                        "external_login_state_max_pending": 5000
                    })
                    .to_string(),
                ))
                .expect("security limits zero qps"),
        )
        .await
        .expect("security limits zero qps response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = json(response).await;
    assert_eq!(error["code"], "invalid_security_limits");

    // 4. 非法值（负数）返回 400
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 10,
                        "authorization_code_ttl_seconds": 120,
                        "pending_request_ttl_seconds": 300,
                        "max_pending_requests_per_client": 15,
                        "max_pending_requests_global": 500,
                        "auth_failure_window_seconds": 600,
                        "account_failure_limit": -1,
                        "ip_failure_limit": 20,
                        "totp_ticket_failure_limit": 3,
                        "external_login_state_ttl_seconds": 300,
                        "external_login_state_rate_window_seconds": 30,
                        "external_login_state_rate_limit": 15,
                        "external_login_state_max_pending": 5000
                    })
                    .to_string(),
                ))
                .expect("security limits negative limit"),
        )
        .await
        .expect("security limits negative limit response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 5. 越上界（#260）返回 400：i64::MAX 的失败阈值等于关掉账户锁定
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 10,
                        "authorization_code_ttl_seconds": 120,
                        "pending_request_ttl_seconds": 300,
                        "max_pending_requests_per_client": 15,
                        "max_pending_requests_global": 500,
                        "auth_failure_window_seconds": 600,
                        "account_failure_limit": i64::MAX,
                        "ip_failure_limit": 20,
                        "totp_ticket_failure_limit": 3,
                        "external_login_state_ttl_seconds": 300,
                        "external_login_state_rate_window_seconds": 30,
                        "external_login_state_rate_limit": 15,
                        "external_login_state_max_pending": 5000
                    })
                    .to_string(),
                ))
                .expect("security limits saturated limit"),
        )
        .await
        .expect("security limits saturated limit response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = json(response).await;
    assert_eq!(error["code"], "invalid_security_limits");

    // 6. 授权码 TTL 超过 RFC 6749 §4.1.2 的 10 分钟建议返回 400（#260 起改为硬上界）
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 10,
                        "authorization_code_ttl_seconds": 3600,
                        "pending_request_ttl_seconds": 300,
                        "max_pending_requests_per_client": 15,
                        "max_pending_requests_global": 500,
                        "auth_failure_window_seconds": 600,
                        "account_failure_limit": 5,
                        "ip_failure_limit": 20,
                        "totp_ticket_failure_limit": 3,
                        "external_login_state_ttl_seconds": 300,
                        "external_login_state_rate_window_seconds": 30,
                        "external_login_state_rate_limit": 15,
                        "external_login_state_max_pending": 5000
                    })
                    .to_string(),
                ))
                .expect("security limits long code ttl"),
        )
        .await
        .expect("security limits long code ttl response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 7. 无 authorization 返回 401
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/security-limits")
                .body(Body::empty())
                .expect("unauthorized security limits get"),
        )
        .await
        .expect("unauthorized security limits get response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // cleanup: 恢复默认值
    let _ = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/security-limits")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "unauthenticated_source_qps": 30,
                        "authorization_code_ttl_seconds": 300,
                        "pending_request_ttl_seconds": 600,
                        "max_pending_requests_per_client": 20,
                        "max_pending_requests_global": 1000,
                        "auth_failure_window_seconds": 900,
                        "account_failure_limit": 10,
                        "ip_failure_limit": 30,
                        "totp_ticket_failure_limit": 5,
                        "external_login_state_ttl_seconds": 600,
                        "external_login_state_rate_window_seconds": 60,
                        "external_login_state_rate_limit": 30,
                        "external_login_state_max_pending": 10000
                    })
                    .to_string(),
                ))
                .expect("security limits reset"),
        )
        .await;

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}
