use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use totp_rs::TOTP;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use crate::harness::HarnessBuilder;
use crate::http;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let harness = HarnessBuilder::new("oauth_ui_api")
        .admin_token("oauth-ui-admin-token")
        .bootstrap_owner()
        .build()
        .await;
    (harness.router, harness.database, harness.key_directory)
}

fn request_id(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("request URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id")
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer oauth-ui-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
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
    let client = http::json_body(response).await;
    let client_id = client["client_id"].as_str().expect("client id");
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Foauth-ui.example%2Fcallback&response_type=code&scope=openid%20profile&state=oauth-ui-state&nonce=oauth-ui-nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
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
    let login_location = http::location(&response);
    let request_id = request_id(&login_location);
    let authz_holder_cookie = http::set_cookies(&response);

    // SPA logs in over JSON, then enrolls TOTP through the authenticated security API.
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
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookies = http::set_cookies(&response);
    let csrf = session_cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned();
    assert!(
        http::json_body(response).await["expires_at"]
            .as_str()
            .is_some()
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/start")
                .header("content-type", "application/json")
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::from(serde_json::json!({}).to_string()))
                .expect("totp setup request"),
        )
        .await
        .expect("totp setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = http::json_body(response).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth url")).expect("TOTP");
    let enrollment_id = setup["enrollment_id"].as_str().expect("enrollment id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/confirm")
                .header("content-type", "application/json")
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": enrollment_id,
                        "code": totp.generate_current().expect("TOTP code")
                    })
                    .to_string(),
                ))
                .expect("totp login request"),
        )
        .await
        .expect("TOTP enrollment confirmation response");
    assert_eq!(response.status(), StatusCode::OK);

    // Bind the session to the pending authorization request created by /oauth/authorize.
    // 持有者 Cookie 来自 authorize 响应，会话 Cookie 来自密码登录。
    let session_cookies = format!("{session_cookies}; {authz_holder_cookie}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("bind request"),
        )
        .await
        .expect("bind response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

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
    let pending = http::json_body(response).await;
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
    let approved = http::json_body(response).await;
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
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("replay approval request"),
        )
        .await
        .expect("replay approval response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(response).await["code"],
        "authorization_request_expired"
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
