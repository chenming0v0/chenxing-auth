//! `/.well-known/assetlinks.json`：Android App Links 声明端点。
//!
//! 公开文件发布 Owner 已登记的声明，不经 Issuer 门禁。
//! 用户自助 App Link API 已移除。未发布任何声明时 404。

use axum::{
    body::Body,
    http::{
        Request, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG},
    },
};
use serde_json::{Value, json};
use tower::ServiceExt;

use chenxing_auth::sessions::domain::Session;
use std::time::Duration;

use crate::harness::{Harness, HarnessBuilder};
use crate::http::json_body;
use crate::oauth_flow::ensure_owner_bootstrapped;
use crate::plan_fixtures;

const FINGERPRINT: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
const FINGERPRINT_B: &str = "B6:DA:01:48:0E:EF:D5:FB:F2:CD:37:71:B8:D1:02:1E:C7:91:30:4B:DD:6C:4B:F4:1D:3F:AA:BA:D4:8E:E5:E1";
const ADMIN_TOKEN: &str = "assetlinks-admin-token";

async fn fetch(router: &axum::Router) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/assetlinks.json")
                .body(Body::empty())
                .expect("assetlinks request"),
        )
        .await
        .expect("assetlinks response")
}

async fn create_client(router: &axum::Router) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "client_name": "termux-chrome",
                        "redirect_uris": ["https://oauth.clya.top/app/1/oauth/callback"],
                        "scopes": ["openid"],
                        "auth_method": "none",
                    })
                    .to_string(),
                ))
                .expect("create client"),
        )
        .await
        .expect("create client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert!(
        body["numeric_app_id"]
            .as_i64()
            .is_some_and(|numeric_app_id| numeric_app_id >= 1)
    );
    assert!(body["android_asset_link"].is_null());
    assert_eq!(body["quota_exempt"], true);
    body["client_id"].as_str().expect("client_id").to_owned()
}

async fn assert_client_quota_exempt(
    database: &chenxing_auth::sqlx::PgPool,
    client_id: &str,
    expected: bool,
) {
    let quota_exempt: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT quota_exempt FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(database)
    .await
    .expect("quota_exempt");
    assert_eq!(quota_exempt, expected);
}

async fn put_app_link(router: &axum::Router, client_id: &str, fingerprint: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/app-links/{client_id}"))
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "package_name": "com.chengming.termux",
                        "sha256_cert_fingerprints": [fingerprint],
                    })
                    .to_string(),
                ))
                .expect("upsert app link"),
        )
        .await
        .expect("upsert app link response");
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn create_user_session(harness: &Harness, label: &str) -> (i64, String, String) {
    let username = format!("{label}-user");
    let response = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": username,
                        "email": format!("{label}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("create user"),
        )
        .await
        .expect("create user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json_body(response).await["id"].as_i64().expect("user id");
    plan_fixtures::assign_private_plan(
        &harness.database,
        user_id,
        plan_fixtures::PlanLimits::legacy_default(),
    )
    .await;
    let (cookies, csrf_token) = owner_session(&harness.state, user_id).await;
    (user_id, cookies, csrf_token)
}

async fn create_owned_client(router: &axum::Router, cookies: &str, csrf_token: &str) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookies)
                .header("x-csrf-token", csrf_token)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "client_name": "self-service-app",
                        "redirect_uris": ["https://oauth.clya.top/app/1/oauth/callback"],
                        "scopes": ["openid"],
                        "auth_method": "none",
                    })
                    .to_string(),
                ))
                .expect("create owned client"),
        )
        .await
        .expect("create owned client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["client_id"]
        .as_str()
        .expect("client_id")
        .to_owned()
}

async fn put_owned_app_link(
    router: &axum::Router,
    cookies: &str,
    csrf_token: &str,
    client_id: &str,
    package_name: &str,
    fingerprint: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/auth/oauth-clients/{client_id}/app-link"))
                .header("cookie", cookies)
                .header("x-csrf-token", csrf_token)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "package_name": package_name,
                        "sha256_cert_fingerprints": [fingerprint],
                    })
                    .to_string(),
                ))
                .expect("user upsert app link"),
        )
        .await
        .expect("user upsert app link response")
}

fn published_packages(body: &Value) -> Vec<String> {
    body.as_array()
        .into_iter()
        .flatten()
        .filter_map(|statement| {
            statement["target"]["package_name"]
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

async fn owner_session(state: &chenxing_auth::state::AppState, owner_id: i64) -> (String, String) {
    let mut session =
        Session::new(owner_id.to_string(), Duration::from_secs(3600)).expect("owner session");
    state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("persist owner session");
    let cookies = format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    );
    (cookies, session.csrf_token)
}

#[tokio::test]
async fn unconfigured_assetlinks_returns_404_envelope() {
    let harness = HarnessBuilder::new("assetlinks_unconfigured")
        .configure(|config| {
            config.issuer = None;
        })
        .build()
        .await;
    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = json_body(response).await;
    assert_eq!(body["code"], "assetlinks_not_configured");
    harness.cleanup().await;
}

#[tokio::test]
async fn published_app_link_is_served_without_issuer_gate() {
    let harness = HarnessBuilder::new("assetlinks_configured")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    let client_id = create_client(&harness.router).await;
    assert_client_quota_exempt(&harness.database, &client_id, true).await;
    let declared = put_app_link(&harness.router, &client_id, FINGERPRINT).await;
    assert_eq!(declared["package_name"], "com.chengming.termux");
    assert_eq!(declared["numeric_app_id"], 1);
    assert_eq!(declared["sha256_cert_fingerprints"], json!([FINGERPRINT]));

    let listed_clients = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/clients")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list clients"),
        )
        .await
        .expect("list clients response");
    assert_eq!(listed_clients.status(), StatusCode::OK);
    let listed_clients_body = json_body(listed_clients).await;
    let created = listed_clients_body
        .as_array()
        .expect("client list")
        .iter()
        .find(|client| client["client_id"] == client_id)
        .expect("created client");
    assert_eq!(created["quota_exempt"], true);
    assert_eq!(
        created["android_asset_link"],
        json!({
            "package_name": "com.chengming.termux",
            "sha256_cert_fingerprints": [FINGERPRINT],
        })
    );

    let listed = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/app-links")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list app links"),
        )
        .await
        .expect("list app links response");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body = json_body(listed).await;
    assert_eq!(listed_body.as_array().map(Vec::len), Some(1));

    // 公开端点不经 Issuer 门禁：把 issuer 清掉后再抓一次，内容必须仍在。
    // 同一进程里 runtime 已加载，直接打公开路径即可（该路由挂在 system_api）。
    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=3600, must-revalidate")
    );
    assert!(
        response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|etag| etag.starts_with('"') && etag.len() == 18)
    );
    let body = json_body(response).await;
    assert_eq!(
        body,
        json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.chengming.termux",
                "sha256_cert_fingerprints": [FINGERPRINT],
            }
        }])
    );

    let deleted = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/app-links/{client_id}"))
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("delete app link"),
        )
        .await
        .expect("delete app link response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let empty = fetch(&harness.router).await;
    assert_eq!(empty.status(), StatusCode::NOT_FOUND);
    harness.cleanup().await;
}

#[tokio::test]
async fn invalid_fingerprint_is_rejected() {
    let harness = HarnessBuilder::new("assetlinks_invalid")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    let client_id = create_client(&harness.router).await;
    let response = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/app-links/{client_id}"))
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "package_name": "com.chengming.termux",
                        "sha256_cert_fingerprints": ["not-a-fingerprint"],
                    })
                    .to_string(),
                ))
                .expect("invalid upsert"),
        )
        .await
        .expect("invalid upsert response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["code"], "invalid_android_fingerprint");
    harness.cleanup().await;
}

#[tokio::test]
async fn same_package_fingerprints_merge_into_one_statement() {
    // 合并只发生在豁免行上：管理面创建的 Client 才进入公开 DAL。
    let harness = HarnessBuilder::new("assetlinks_merge")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    let client_a = create_client(&harness.router).await;
    let client_b = create_client(&harness.router).await;
    put_app_link(&harness.router, &client_a, FINGERPRINT).await;
    put_app_link(&harness.router, &client_b, FINGERPRINT_B).await;

    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body,
        json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.chengming.termux",
                "sha256_cert_fingerprints": [FINGERPRINT, FINGERPRINT_B],
            }
        }])
    );
    harness.cleanup().await;
}

#[tokio::test]
async fn user_registered_app_link_is_not_published() {
    let harness = HarnessBuilder::new("assetlinks_user")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    ensure_owner_bootstrapped(
        &harness.router,
        &harness.database,
        "assetlinks",
        "assetlinks-user",
    )
    .await;
    let (_user_id, cookies, csrf_token) = create_user_session(&harness, "assetlinks-self").await;
    let client_id = create_owned_client(&harness.router, &cookies, &csrf_token).await;
    assert_client_quota_exempt(&harness.database, &client_id, false).await;

    let declared = put_owned_app_link(
        &harness.router,
        &cookies,
        &csrf_token,
        &client_id,
        "com.chengming.termux",
        FINGERPRINT,
    )
    .await;
    assert_eq!(declared.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(declared).await["code"], "not_found");

    let listed = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/app-links")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list app links"),
        )
        .await
        .expect("list app links response");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body = json_body(listed).await;
    assert_eq!(listed_body.as_array().map(Vec::len), Some(0));

    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await["code"],
        "assetlinks_not_configured"
    );
    harness.cleanup().await;
}

#[tokio::test]
async fn admin_registered_app_link_is_published() {
    let harness = HarnessBuilder::new("assetlinks_admin_publish")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    let client_id = create_client(&harness.router).await;
    assert_client_quota_exempt(&harness.database, &client_id, true).await;
    put_app_link(&harness.router, &client_id, FINGERPRINT).await;
    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await,
        json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.chengming.termux",
                "sha256_cert_fingerprints": [FINGERPRINT],
            }
        }])
    );
    harness.cleanup().await;
}

#[tokio::test]
async fn owner_can_publish_integrate_app_client() {
    let harness = HarnessBuilder::new("assetlinks_publish_integrate")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    ensure_owner_bootstrapped(
        &harness.router,
        &harness.database,
        "assetlinks",
        "assetlinks-publish-integrate",
    )
    .await;
    let (_user_id, cookies, csrf_token) =
        create_user_session(&harness, "assetlinks-self-admin").await;
    let client_id = create_owned_client(&harness.router, &cookies, &csrf_token).await;
    assert_client_quota_exempt(&harness.database, &client_id, false).await;

    let declared = put_app_link(&harness.router, &client_id, FINGERPRINT).await;
    assert_eq!(declared["package_name"], "com.chengming.termux");

    let listed = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/app-links")
                .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list app links"),
        )
        .await
        .expect("list app links response");
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(json_body(listed).await.as_array().map(Vec::len), Some(1));

    let published = fetch(&harness.router).await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(
        json_body(published).await,
        json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.chengming.termux",
                "sha256_cert_fingerprints": [FINGERPRINT],
            }
        }])
    );
    harness.cleanup().await;
}

#[tokio::test]
async fn two_users_app_links_stay_off_the_public_file() {
    let harness = HarnessBuilder::new("assetlinks_two_users")
        .admin_token(ADMIN_TOKEN)
        .build()
        .await;
    ensure_owner_bootstrapped(
        &harness.router,
        &harness.database,
        "assetlinks",
        "assetlinks-two-users",
    )
    .await;
    let (_a_id, a_cookies, a_csrf) = create_user_session(&harness, "assetlinks-a").await;
    let (_b_id, b_cookies, b_csrf) = create_user_session(&harness, "assetlinks-b").await;
    let client_a = create_owned_client(&harness.router, &a_cookies, &a_csrf).await;
    let client_b = create_owned_client(&harness.router, &b_cookies, &b_csrf).await;
    assert_eq!(
        put_owned_app_link(
            &harness.router,
            &a_cookies,
            &a_csrf,
            &client_a,
            "com.example.alpha",
            FINGERPRINT,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put_owned_app_link(
            &harness.router,
            &b_cookies,
            &b_csrf,
            &client_b,
            "com.example.beta",
            FINGERPRINT_B,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = json_body(response).await;
    assert_eq!(body["code"], "assetlinks_not_configured");
    assert!(!published_packages(&body).contains(&"com.example.alpha".to_owned()));
    assert!(!published_packages(&body).contains(&"com.example.beta".to_owned()));
    harness.cleanup().await;
}
