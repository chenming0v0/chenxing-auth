use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::http;

const ADMIN: &str = "admin-smtp-password-token";
const SECRET: &str = "super-secret-smtp";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let harness = crate::harness::HarnessBuilder::new("admin_smtp_password")
        .admin_token(ADMIN)
        .build()
        .await;
    (harness.router, harness.database, harness.key_directory)
}

fn smtp_body(password_action: Option<&str>, password: Option<&str>) -> String {
    let mut body = json!({
        "host": "smtp.example.com",
        "port": 587,
        "username": "noreply@example.com",
        "from_address": "辰星认证中枢 <noreply@example.com>",
        "ssl_enabled": true,
        "force_auth_login": false,
    });
    if let Some(action) = password_action {
        body["password_action"] = json!(action);
    }
    if let Some(value) = password {
        body["password"] = json!(value);
    }
    body.to_string()
}

async fn put_smtp(
    router: &Router,
    password_action: Option<&str>,
    password: Option<&str>,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", format!("Bearer {ADMIN}"))
                .header("content-type", "application/json")
                .body(Body::from(smtp_body(password_action, password)))
                .expect("smtp put"),
        )
        .await
        .expect("smtp put response")
}

async fn get_smtp(router: &Router) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(Body::empty())
                .expect("smtp get"),
        )
        .await
        .expect("smtp get response")
}

fn assert_redacted(body: &Value) {
    assert!(body.get("password").is_none(), "{body}");
    assert!(body.get("password_ciphertext").is_none(), "{body}");
    let rendered = body.to_string();
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(!rendered.contains("password_ciphertext"), "{rendered}");
}

async fn stored_smtp(database: &chenxing_auth::sqlx::PgPool) -> Value {
    let raw: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'smtp'",
    )
    .fetch_one(database)
    .await
    .expect("smtp row");
    match raw {
        Some(value) if !value.trim().is_empty() => serde_json::from_str(&value).expect("smtp JSON"),
        _ => json!({}),
    }
}

#[tokio::test]
async fn smtp_password_update_is_explicit_keep_set_clear() {
    let (router, database, key_directory) = setup().await;

    let response = get_smtp(&router).await;
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = http::json_body(response).await;
    assert_eq!(smtp["password_configured"], false);
    assert_redacted(&smtp);

    let response = put_smtp(&router, Some("set"), Some(SECRET)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = http::json_body(response).await;
    assert_eq!(smtp["password_configured"], true);
    assert_redacted(&smtp);
    let after_set = stored_smtp(&database).await;
    let ciphertext = after_set["password_ciphertext"]
        .as_str()
        .expect("ciphertext after set")
        .to_owned();
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, SECRET);

    let response = put_smtp(&router, Some("keep"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = http::json_body(response).await;
    assert_eq!(smtp["password_configured"], true);
    assert_redacted(&smtp);
    assert_eq!(
        stored_smtp(&database).await["password_ciphertext"],
        ciphertext
    );

    let response = put_smtp(&router, None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(http::json_body(response).await["password_configured"], true);
    assert_eq!(
        stored_smtp(&database).await["password_ciphertext"],
        ciphertext
    );

    let response = put_smtp(&router, Some("clear"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = http::json_body(response).await;
    assert_eq!(smtp["password_configured"], false);
    assert_redacted(&smtp);
    let after_clear = stored_smtp(&database).await;
    assert!(
        after_clear.get("password_ciphertext").is_none()
            || after_clear["password_ciphertext"].is_null()
    );

    let response = get_smtp(&router).await;
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = http::json_body(response).await;
    assert_eq!(smtp["password_configured"], false);
    assert_redacted(&smtp);

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn smtp_password_rejects_conflicts_and_empty_string_keep() {
    let (router, database, key_directory) = setup().await;

    let response = put_smtp(&router, Some("set"), Some(SECRET)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let ciphertext = stored_smtp(&database).await["password_ciphertext"]
        .as_str()
        .expect("ciphertext")
        .to_owned();

    for (action, password, code_fragment) in [
        (None, Some(""), "conflicts"),
        (Some("keep"), Some(SECRET), "conflicts"),
        (Some("keep"), Some(""), "conflicts"),
        (Some("clear"), Some(SECRET), "conflicts"),
        (Some("clear"), Some(""), "conflicts"),
        (Some("set"), None, "required"),
    ] {
        let response = put_smtp(&router, action, password).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{action:?}");
        let error = http::json_body(response).await;
        assert_eq!(error["code"], "invalid_smtp_setting", "{action:?}");
        assert!(
            error["message"]
                .as_str()
                .is_some_and(|message| message.contains(code_fragment)),
            "{error} {action:?}"
        );
        assert_redacted(&error);
        assert_eq!(
            stored_smtp(&database).await["password_ciphertext"],
            ciphertext,
            "rejected write must not consume the saved ciphertext"
        );
    }

    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}
