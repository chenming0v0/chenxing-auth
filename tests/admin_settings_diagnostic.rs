//! 管理设置 GET 用响应头暴露可修复诊断，JSON body 保持设置对象本身（#448）。

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

const DIAGNOSTIC_HEADER: &str = "x-chenxing-setting-diagnostic";
const ADMIN: &str = "Bearer admin-settings-diagnostic-token";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_settings_diagnostic", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!(
        "chenxing-admin-settings-diagnostic-{}",
        Uuid::new_v4()
    ));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-settings-diagnostic-token".to_owned();
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

async fn store_setting(database: &chenxing_auth::sqlx::PgPool, key: &str, value: &str) {
    chenxing_auth::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(key)
    .bind(value)
    .execute(database)
    .await
    .expect("store setting");
}

async fn get_setting(router: &Router, path: &str) -> (StatusCode, Option<String>, Value, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", ADMIN)
                .body(Body::empty())
                .expect("settings get"),
        )
        .await
        .expect("settings get response");
    let status = response.status();
    let diagnostic = response
        .headers()
        .get(DIAGNOSTIC_HEADER)
        .map(|value| value.to_str().expect("ascii header").to_owned());
    let raw = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    let body = serde_json::from_str(&raw).expect("JSON");
    (status, diagnostic, body, raw)
}

#[tokio::test]
async fn unconfigured_and_valid_reads_omit_the_diagnostic_header() {
    let (router, database, key_directory) = setup().await;

    for path in [
        "/api/v1/admin/settings/passkey",
        "/api/v1/admin/settings/email-policy",
        "/api/v1/admin/settings/security-limits",
    ] {
        let (status, diagnostic, _, raw) = get_setting(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            diagnostic, None,
            "unconfigured {path} must not advertise repair"
        );
        assert!(!raw.contains(DIAGNOSTIC_HEADER));
    }

    store_setting(
        &database,
        "security_limits",
        r#"{
            "unauthenticated_source_qps": 8,
            "authorization_code_ttl_seconds": 120,
            "pending_request_ttl_seconds": 600,
            "max_pending_requests_per_client": 20,
            "max_pending_requests_global": 1000,
            "auth_failure_window_seconds": 900,
            "account_failure_limit": 4,
            "ip_failure_limit": 30,
            "totp_ticket_failure_limit": 5,
            "external_login_state_ttl_seconds": 600,
            "external_login_state_rate_window_seconds": 60,
            "external_login_state_rate_limit": 30,
            "external_login_state_max_pending": 10000
        }"#,
    )
    .await;
    let (status, diagnostic, body, _) =
        get_setting(&router, "/api/v1/admin/settings/security-limits").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(diagnostic, None);
    assert_eq!(body["account_failure_limit"], 4);

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn invalid_stored_settings_return_200_with_invalid_header() {
    let (router, database, key_directory) = setup().await;

    store_setting(
        &database,
        "passkey",
        r#"{
            "enabled": true,
            "rp_name": "辰星认证中枢",
            "rp_id": "com",
            "user_verification": "preferred",
            "authenticator_attachment": "any",
            "allow_insecure_origin": false,
            "allowed_origins": ["https://evil.com"]
        }"#,
    )
    .await;
    store_setting(
        &database,
        "email_policy",
        r#"{"whitelist_enabled":true,"alias_restriction_enabled":false,"allowed_domains":[]}"#,
    )
    .await;
    store_setting(
        &database,
        "security_limits",
        r#"{
            "unauthenticated_source_qps": 30,
            "authorization_code_ttl_seconds": 86400,
            "pending_request_ttl_seconds": 600,
            "max_pending_requests_per_client": 20,
            "max_pending_requests_global": 1000,
            "auth_failure_window_seconds": 900,
            "account_failure_limit": 9223372036854775807,
            "ip_failure_limit": 0,
            "totp_ticket_failure_limit": 5,
            "external_login_state_ttl_seconds": 600,
            "external_login_state_rate_window_seconds": 60,
            "external_login_state_rate_limit": 30,
            "external_login_state_max_pending": 10000
        }"#,
    )
    .await;

    let cases = [
        ("/api/v1/admin/settings/passkey", "rp_id", "com"),
        (
            "/api/v1/admin/settings/email-policy",
            "whitelist_enabled",
            "true",
        ),
        (
            "/api/v1/admin/settings/security-limits",
            "account_failure_limit",
            "9223372036854775807",
        ),
    ];
    for (path, field, _) in cases {
        let (status, diagnostic, body, raw) = get_setting(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(diagnostic.as_deref(), Some("invalid"), "{path}");
        assert!(
            body.get(field).is_some(),
            "{path} body must stay the setting object"
        );
        assert!(!raw.contains("setting validation failed"), "{path}");
    }

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn corrupt_stored_settings_return_defaults_and_corrupt_header() {
    let (router, database, key_directory) = setup().await;
    const MARKER: &str = "SECRET-MARKER";

    for (key, field) in [
        ("passkey", "enabled"),
        ("email_policy", "whitelist_enabled"),
        ("security_limits", "unauthenticated_source_qps"),
    ] {
        store_setting(&database, key, &format!(r#"{{"{field}":"{MARKER}"}}"#)).await;
    }

    for path in [
        "/api/v1/admin/settings/passkey",
        "/api/v1/admin/settings/email-policy",
        "/api/v1/admin/settings/security-limits",
    ] {
        let (status, diagnostic, _, raw) = get_setting(&router, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(diagnostic.as_deref(), Some("corrupt"), "{path}");
        assert!(
            !raw.contains(MARKER),
            "response must not echo stored payload: {path} {raw}"
        );
    }

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}
