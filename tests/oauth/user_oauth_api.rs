use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::SET_COOKIE},
};
use totp_rs::TOTP;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

// 迁移不再种子默认套餐：自助创建 Client 的用例必须自己给用户挂套餐，
// 否则会被自助接入闸门拒绝（403 self_service_disabled）。
use crate::harness::HarnessBuilder;
use crate::http;
use crate::oauth_flow;
use crate::plan_fixtures;

use oauth_flow::ensure_owner_bootstrapped;

const TEST_ORIGIN: &str = "http://127.0.0.1:3000/";

fn resolve_location(location: &str) -> Url {
    Url::parse(TEST_ORIGIN)
        .expect("test origin")
        .join(location)
        .expect("valid redirect location")
}

/// schema 隔离替代了跨测试套餐锁：每个测试用例在自己的 schema 里跑，
/// `DELETE FROM plans` 只删自己的 schema，不会破坏其他二进制的套餐。
async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let harness = HarnessBuilder::new("user_oauth_api")
        .admin_token("user-ui-admin-token")
        .build()
        .await;
    ensure_owner_bootstrapped(
        &harness.router,
        &harness.database,
        "user_oauth_api",
        "user-oauth-api",
    )
    .await;
    (harness.router, harness.database, harness.key_directory)
}

fn csrf(cookies: &str) -> &str {
    cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
}

/// 注册 + 登录，并给该用户挂一个限额等于原迁移种子（2 / 2500 / 50000）的私有
/// 套餐。原来这些断言依赖迁移自带的默认套餐，种子删除后必须显式声明前提。
async fn register_and_login(
    router: &Router,
    database: &chenxing_auth::sqlx::PgPool,
    suffix: &str,
) -> (String, String) {
    let credentials = register_and_login_without_plan(router, suffix).await;
    plan_fixtures::assign_private_plan_by_username(
        database,
        &format!("ui-{suffix}"),
        plan_fixtures::PlanLimits::legacy_default(),
    )
    .await;
    credentials
}

async fn register_and_login_without_plan(router: &Router, suffix: &str) -> (String, String) {
    let email = format!("ui-{suffix}@example.com");
    let username = format!("ui-{suffix}");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer user-ui-admin-token")
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
    let cookie_header = http::set_cookies(&response);
    let csrf_token = csrf(&cookie_header).to_owned();
    assert!(cookie_header.contains("chenxing_session="));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/start")
                .header("content-type", "application/json")
                .header("cookie", &cookie_header)
                .header("x-csrf-token", &csrf_token)
                .body(Body::from(serde_json::json!({}).to_string()))
                .expect("TOTP setup request"),
        )
        .await
        .expect("TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = http::json_body(response).await;
    let enrollment_id = setup["enrollment_id"].as_str().expect("TOTP enrollment ID");
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/confirm")
                .header("content-type", "application/json")
                .header("cookie", &cookie_header)
                .header("x-csrf-token", &csrf_token)
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": enrollment_id,
                        "code": totp.generate_current().expect("TOTP code")
                    })
                    .to_string(),
                ))
                .expect("TOTP confirmation request"),
        )
        .await
        .expect("TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);
    (cookie_header, csrf_token)
}

fn client_input(index: usize) -> String {
    serde_json::json!({
        "client_name": format!("User App {index}"),
        "redirect_uris": [format!("https://user-{index}.example/callback")],
        "scopes": ["openid", "profile"]
    })
    .to_string()
}

const APP_LINK_FINGERPRINT: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";

async fn create_owned_client(
    router: &Router,
    cookies: &str,
    csrf_token: &str,
    index: usize,
) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookies)
                .header("x-csrf-token", csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(client_input(index)))
                .expect("create client request"),
        )
        .await
        .expect("create client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    http::json_body(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned()
}

fn app_link_body(package_name: &str, fingerprint: &str) -> String {
    serde_json::json!({
        "package_name": package_name,
        "sha256_cert_fingerprints": [fingerprint],
    })
    .to_string()
}

async fn put_owned_app_link(
    router: &Router,
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
                .header("content-type", "application/json")
                .body(Body::from(app_link_body(package_name, fingerprint)))
                .expect("put app link request"),
        )
        .await
        .expect("put app link response")
}

async fn listed_asset_link(router: &Router, cookies: &str, client_id: &str) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookies)
                .body(Body::empty())
                .expect("list clients request"),
        )
        .await
        .expect("list clients response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    body["items"]
        .as_array()
        .expect("client items")
        .iter()
        .find(|item| item["client_id"] == client_id)
        .expect("owned client")
        .get("android_asset_link")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn normal_user_can_create_only_two_owned_oauth_projects() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;
    for index in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/oauth-clients")
                    .header("cookie", &cookies)
                    .header("x-csrf-token", &csrf_token)
                    .header("content-type", "application/json")
                    .body(Body::from(client_input(index)))
                    .expect("create client request"),
            )
            .await
            .expect("create client response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = http::json_body(response).await;
        assert!(created["client_secret"].as_str().is_some());
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(client_input(2)))
                .expect("third client request"),
        )
        .await
        .expect("third client response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        http::json_body(response).await["code"],
        "oauth_client_quota_exceeded"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("list clients request"),
        )
        .await
        .expect("list clients response");
    assert_eq!(response.status(), StatusCode::OK);
    let clients = http::json_body(response).await;
    assert_eq!(clients["items"].as_array().expect("client items").len(), 2);
    assert_eq!(clients["items"][0]["quota"]["daily_limit"], 2_500);
    assert_eq!(clients["items"][0]["quota"]["monthly_limit"], 50_000);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("admin list request"),
        )
        .await
        .expect("admin list response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/status")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("status request"),
        )
        .await
        .expect("status response");
    assert_eq!(http::json_body(response).await["authenticated"], true);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("profile request"),
        )
        .await
        .expect("profile response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn normal_user_cannot_read_or_mutate_another_users_oauth_project() {
    let (router, database, key_directory) = setup().await;
    let owner_suffix = Uuid::new_v4().simple().to_string();
    let (owner_cookies, owner_csrf) = register_and_login(&router, &database, &owner_suffix).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &owner_cookies)
                .header("x-csrf-token", &owner_csrf)
                .header("content-type", "application/json")
                .body(Body::from(client_input(9)))
                .expect("owner client request"),
        )
        .await
        .expect("owner client response");
    let client_id = http::json_body(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();

    let other_suffix = Uuid::new_v4().simple().to_string();
    let (other_cookies, other_csrf) = register_and_login(&router, &database, &other_suffix).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &other_cookies)
                .body(Body::empty())
                .expect("other list request"),
        )
        .await
        .expect("other list response");
    assert!(
        http::json_body(response).await["items"]
            .as_array()
            .expect("other items")
            .is_empty()
    );

    for (method, suffix) in [
        ("PUT", ""),
        ("DELETE", ""),
        ("POST", "/disable"),
        ("POST", "/enable"),
        ("POST", "/rotate-secret"),
    ] {
        let uri = format!("/api/v1/auth/oauth-clients/{client_id}{suffix}");
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", &other_cookies)
            .header("x-csrf-token", &other_csrf);
        if method == "PUT" {
            builder = builder.header("content-type", "application/json");
        }
        let body = if method == "PUT" {
            Body::from(client_input(10))
        } else {
            Body::empty()
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("other mutation request"))
            .await
            .expect("other mutation response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email IN ($1, $2)")
        .bind(format!("ui-{owner_suffix}@example.com"))
        .bind(format!("ui-{other_suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owned_client_mutations_require_user_csrf() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, _) = register_and_login(&router, &database, &suffix).await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .header("content-type", "application/json")
                .body(Body::from(client_input(0)))
                .expect("missing csrf request"),
        )
        .await
        .expect("missing csrf response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(http::json_body(response).await["code"], "csrf_invalid");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owned_client_delete_frees_quota_cascades_consents_and_requires_csrf() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;

    let mut client_ids = Vec::new();
    for index in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/oauth-clients")
                    .header("cookie", &cookies)
                    .header("x-csrf-token", &csrf_token)
                    .header("content-type", "application/json")
                    .body(Body::from(client_input(index)))
                    .expect("create client request"),
            )
            .await
            .expect("create client response");
        assert_eq!(response.status(), StatusCode::CREATED);
        client_ids.push(
            http::json_body(response).await["client_id"]
                .as_str()
                .expect("client id")
                .to_owned(),
        );
    }

    let user_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(format!("ui-{suffix}"))
            .fetch_one(&database)
            .await
            .expect("user id");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2",
    )
    .bind(user_id)
    .bind(&client_ids[0])
    .bind(serde_json::json!(["openid"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("consent insert");

    let missing_csrf = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/oauth-clients/{}", client_ids[0]))
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("delete without csrf"),
        )
        .await
        .expect("delete without csrf response");
    assert_eq!(missing_csrf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(http::json_body(missing_csrf).await["code"], "csrf_invalid");

    let deleted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/oauth-clients/{}", client_ids[0]))
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .expect("delete client request"),
        )
        .await
        .expect("delete client response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_ids[0])
    .fetch_one(&database)
    .await
    .expect("deleted client count");
    assert_eq!(remaining, 0);

    let consents: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_consents WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&database)
            .await
            .expect("cascaded consent count");
    assert_eq!(consents, 0);

    let audits: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_delete' AND resource_id = $1",
    )
    .bind(&client_ids[0])
    .fetch_one(&database)
    .await
    .expect("delete audit count");
    assert_eq!(audits, 1);

    let missing = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/oauth-clients/{}", client_ids[0]))
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .expect("second delete request"),
        )
        .await
        .expect("second delete response");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        http::json_body(missing).await["code"],
        "oauth_client_not_found"
    );

    let replacement = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(client_input(2)))
                .expect("replacement client request"),
        )
        .await
        .expect("replacement client response");
    assert_eq!(replacement.status(), StatusCode::CREATED);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_can_delete_oauth_client() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer user-ui-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Admin Delete {suffix}"),
                        "redirect_uris": ["https://admin-delete.example/callback"],
                        "scopes": ["openid"]
                    })
                    .to_string(),
                ))
                .expect("admin create client request"),
        )
        .await
        .expect("admin create client response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let client_id = http::json_body(created).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();

    let deleted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/clients/{client_id}"))
                .header("authorization", "Bearer user-ui-admin-token")
                .body(Body::empty())
                .expect("admin delete client request"),
        )
        .await
        .expect("admin delete client response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&database)
    .await
    .expect("deleted admin client count");
    assert_eq!(remaining, 0);

    let audits: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_delete' AND resource_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&database)
    .await
    .expect("admin delete audit count");
    assert_eq!(audits, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn authorized_apps_are_user_scoped_and_consent_revoke_is_audited() {
    let (router, database, key_directory) = setup().await;
    let owner_suffix = Uuid::new_v4().simple().to_string();
    let (owner_cookies, owner_csrf) = register_and_login(&router, &database, &owner_suffix).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer user-ui-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Authorized Example",
                        "redirect_uris": ["https://authorized.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client_id = http::json_body(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();

    let other_suffix = Uuid::new_v4().simple().to_string();
    let (other_cookies, _) = register_and_login(&router, &database, &other_suffix).await;
    let owner_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(format!("ui-{owner_suffix}"))
            .fetch_one(&database)
            .await
            .expect("owner id");
    let other_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(format!("ui-{other_suffix}"))
            .fetch_one(&database)
            .await
            .expect("other id");
    for user_id in [owner_id, other_id] {
        chenxing_auth::sqlx::query(
            "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
             SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2",
        )
        .bind(user_id)
        .bind(&client_id)
        .bind(serde_json::json!(["openid", "profile"]))
        .bind(time::OffsetDateTime::now_utc())
        .execute(&database)
        .await
        .expect("consent insert");
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/authorized-apps")
                .header("cookie", &owner_cookies)
                .body(Body::empty())
                .expect("authorized apps request"),
        )
        .await
        .expect("authorized apps response");
    assert_eq!(response.status(), StatusCode::OK);
    let apps = http::json_body(response).await;
    assert_eq!(apps["items"].as_array().expect("authorized items").len(), 1);
    let app = &apps["items"][0];
    assert_eq!(app["client_id"], client_id);
    assert_eq!(app["client_name"], "Authorized Example");
    assert_eq!(app["scopes"], serde_json::json!(["openid", "profile"]));
    assert!(app.get("client_secret").is_none());
    assert!(app.get("client_secret_hash").is_none());
    assert!(app.get("redirect_uris").is_none());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/authorized-apps/{client_id}"))
                .header("cookie", &owner_cookies)
                .body(Body::empty())
                .expect("missing csrf revoke request"),
        )
        .await
        .expect("missing csrf revoke response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(http::json_body(response).await["code"], "csrf_invalid");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/authorized-apps/{client_id}"))
                .header("cookie", &owner_cookies)
                .header("x-csrf-token", &owner_csrf)
                .body(Body::empty())
                .expect("revoke request"),
        )
        .await
        .expect("revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Issue #64：撤销改为软删除，行保留、`revoked_at` 置位。
    // 这里断言「生效授权数为 0」而不是「行数为 0」：撤销事实必须留在库中作为
    // 权威判定依据和审计证据，Redis 丢数据时才能回源。
    let remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE oc.client_id = $1 AND c.user_id = $2 AND c.revoked_at IS NULL",
    )
    .bind(&client_id)
    .bind(owner_id)
    .fetch_one(&database)
    .await
    .expect("owner active consent count");
    assert_eq!(remaining, 0);
    let revoked: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE oc.client_id = $1 AND c.user_id = $2 AND c.revoked_at IS NOT NULL",
    )
    .bind(&client_id)
    .bind(owner_id)
    .fetch_one(&database)
    .await
    .expect("owner revoked consent count");
    assert_eq!(revoked, 1, "revocation must be persisted, not deleted");
    let other_remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE oc.client_id = $1 AND c.user_id = $2 AND c.revoked_at IS NULL",
    )
    .bind(&client_id)
    .bind(other_id)
    .fetch_one(&database)
    .await
    .expect("other active consent count");
    assert_eq!(other_remaining, 1);
    let audit: (Option<i64>, String, String, Option<String>) = chenxing_auth::sqlx::query_as(
        "SELECT actor_user_id, action, resource_type, resource_id FROM audit_events
         WHERE action = 'consent_revoke' AND resource_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&database)
    .await
    .expect("consent audit");
    assert_eq!(
        audit,
        (
            Some(owner_id),
            "consent_revoke".to_owned(),
            "oauth_consent".to_owned(),
            Some(client_id.clone()),
        )
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/authorized-apps/{client_id}"))
                .header("cookie", &owner_cookies)
                .header("x-csrf-token", &owner_csrf)
                .body(Body::empty())
                .expect("idempotent revoke request"),
        )
        .await
        .expect("idempotent revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/authorized-apps")
                .header("cookie", &other_cookies)
                .body(Body::empty())
                .expect("other authorized apps request"),
        )
        .await
        .expect("other authorized apps response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        http::json_body(response).await["items"]
            .as_array()
            .expect("other items")
            .len(),
        1
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(&client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE username IN ($1, $2)")
        .bind(format!("ui-{owner_suffix}"))
        .bind(format!("ui-{other_suffix}"))
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owned_oauth_authorization_consumes_daily_and_monthly_quota() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(client_input(20)))
                .expect("create client request"),
        )
        .await
        .expect("create client response");
    let client_id = http::json_body(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fuser-20.example%2Fcallback&response_type=code&scope=openid%20profile&state=quota-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let consent_url = resolve_location(location);
    assert_eq!(consent_url.path(), "/oauth/consent");
    let request_id = consent_url
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("authorization request id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookies)
                .header("x-csrf-token", csrf(&cookies))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve consent request"),
        )
        .await
        .expect("approve consent response");
    assert_eq!(response.status(), StatusCode::OK);
    let decision = http::json_body(response).await;
    assert_eq!(decision["decision"].as_str(), Some("approve"));
    let redirect = resolve_location(
        decision["redirect_to"]
            .as_str()
            .expect("authorization redirect target"),
    );
    assert!(
        redirect
            .query_pairs()
            .any(|(key, value)| key == "state" && value == "quota-state")
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("list clients request"),
        )
        .await
        .expect("list clients response");
    let clients = http::json_body(response).await;
    let project = clients["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["client_id"] == client_id)
        .expect("owned project");
    assert_eq!(project["quota"]["daily_used"], 1);
    assert_eq!(project["quota"]["monthly_used"], 1);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn disabled_user_cannot_use_an_existing_browser_session() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("ui-{suffix}@example.com");
    let (cookies, _) = register_and_login(&router, &database, &suffix).await;
    let (user_id,) =
        chenxing_auth::sqlx::query_as::<_, (i64,)>("SELECT id FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&database)
            .await
            .expect("user id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/disabled"))
                .header("authorization", "Bearer user-ui-admin-token")
                .body(Body::empty())
                .expect("disable user request"),
        )
        .await
        .expect("disable user response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("disabled user request"),
        )
        .await
        .expect("disabled user response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/active"))
                .header("authorization", "Bearer user-ui-admin-token")
                .body(Body::empty())
                .expect("enable user request"),
        )
        .await
        .expect("enable user response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("old session after re-enable request"),
        )
        .await
        .expect("old session after re-enable response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_can_put_and_clear_app_link_on_own_client() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;
    let client_id = create_owned_client(&router, &cookies, &csrf_token, 1).await;

    let response = put_owned_app_link(
        &router,
        &cookies,
        &csrf_token,
        &client_id,
        "com.chengming.termux",
        APP_LINK_FINGERPRINT,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert_eq!(body["client_id"], client_id);
    assert_eq!(body["package_name"], "com.chengming.termux");
    assert_eq!(
        body["sha256_cert_fingerprints"],
        serde_json::json!([APP_LINK_FINGERPRINT])
    );
    assert!(
        body["numeric_app_id"]
            .as_i64()
            .is_some_and(|numeric_app_id| numeric_app_id >= 1)
    );
    assert_eq!(
        listed_asset_link(&router, &cookies, &client_id).await,
        serde_json::json!({
            "package_name": "com.chengming.termux",
            "sha256_cert_fingerprints": [APP_LINK_FINGERPRINT],
        })
    );
    let audits: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE action = 'client_update' AND resource_id = $1
           AND actor_type = 'user'
           AND metadata->>'field' = 'android_asset_link'",
    )
    .bind(&client_id)
    .fetch_one(&database)
    .await
    .expect("app-link audit count");
    assert_eq!(audits, 1);

    let deleted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/oauth-clients/{client_id}/app-link"))
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .expect("delete app link request"),
        )
        .await
        .expect("delete app link response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(
        listed_asset_link(&router, &cookies, &client_id)
            .await
            .is_null()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_cannot_mutate_another_users_app_link() {
    let (router, database, key_directory) = setup().await;
    let owner_suffix = Uuid::new_v4().simple().to_string();
    let (owner_cookies, owner_csrf) = register_and_login(&router, &database, &owner_suffix).await;
    let client_id = create_owned_client(&router, &owner_cookies, &owner_csrf, 9).await;

    let other_suffix = Uuid::new_v4().simple().to_string();
    let (other_cookies, other_csrf) = register_and_login(&router, &database, &other_suffix).await;
    let response = put_owned_app_link(
        &router,
        &other_cookies,
        &other_csrf,
        &client_id,
        "com.chengming.termux",
        APP_LINK_FINGERPRINT,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        http::json_body(response).await["code"],
        "oauth_client_not_found"
    );

    let deleted = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/oauth-clients/{client_id}/app-link"))
                .header("cookie", &other_cookies)
                .header("x-csrf-token", &other_csrf)
                .body(Body::empty())
                .expect("other delete app link request"),
        )
        .await
        .expect("other delete app link response");
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        http::json_body(deleted).await["code"],
        "oauth_client_not_found"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email IN ($1, $2)")
        .bind(format!("ui-{owner_suffix}@example.com"))
        .bind(format!("ui-{other_suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owned_app_link_rejects_invalid_package_and_fingerprint() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;
    let client_id = create_owned_client(&router, &cookies, &csrf_token, 3).await;

    let package = put_owned_app_link(
        &router,
        &cookies,
        &csrf_token,
        &client_id,
        "termux",
        APP_LINK_FINGERPRINT,
    )
    .await;
    assert_eq!(package.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(package).await["code"],
        "invalid_android_package_name"
    );

    let fingerprint = put_owned_app_link(
        &router,
        &cookies,
        &csrf_token,
        &client_id,
        "com.chengming.termux",
        "not-a-fingerprint",
    )
    .await;
    assert_eq!(fingerprint.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(fingerprint).await["code"],
        "invalid_android_fingerprint"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owned_app_link_update_is_not_blocked_when_self_service_is_closed() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &database, &suffix).await;
    let client_id = create_owned_client(&router, &cookies, &csrf_token, 4).await;
    plan_fixtures::clear_all_plans(&database).await;

    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookies)
                .header("x-csrf-token", &csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(client_input(5)))
                .expect("create after gate closed"),
        )
        .await
        .expect("create after gate closed response");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(refused).await["code"],
        "self_service_disabled"
    );

    let response = put_owned_app_link(
        &router,
        &cookies,
        &csrf_token,
        &client_id,
        "com.chengming.termux",
        APP_LINK_FINGERPRINT,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        listed_asset_link(&router, &cookies, &client_id).await["package_name"],
        "com.chengming.termux"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_token_created_client_belongs_to_first_owner() {
    let (router, database, key_directory) = setup().await;
    let created = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer user-ui-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Admin Token Owner Stamp",
                        "redirect_uris": ["https://admin-token.example/callback"],
                        "scopes": ["openid"]
                    })
                    .to_string(),
                ))
                .expect("admin create client request"),
        )
        .await
        .expect("admin create client response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let client_id = http::json_body(created).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();
    let owner: Option<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT owner_user_id FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&database)
    .await
    .expect("admin client owner");
    let first_owner: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'owner' AND status <> 'disabled' ORDER BY id ASC LIMIT 1",
    )
    .fetch_one(&database)
    .await
    .expect("first active owner");
    assert_eq!(owner, Some(first_owner));
    let _ = std::fs::remove_dir_all(key_directory);
}
