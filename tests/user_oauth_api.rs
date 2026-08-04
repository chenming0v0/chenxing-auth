use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
    response::Response,
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use serde_json::Value;
use totp_rs::TOTP;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

const TEST_ORIGIN: &str = "http://127.0.0.1:3000/";

fn resolve_location(location: &str) -> Url {
    Url::parse(TEST_ORIGIN)
        .expect("test origin")
        .join(location)
        .expect("valid redirect location")
}

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
    let key_directory = std::env::temp_dir().join(format!("chenxing-user-ui-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "user-ui-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("state")),
        database,
        key_directory,
    )
}

async fn json(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

fn cookies(response: &Response) -> String {
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

fn csrf(cookies: &str) -> &str {
    cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
}

async fn register_and_login(router: &Router, suffix: &str) -> (String, String) {
    let email = format!("ui-{suffix}@example.com");
    let username = format!("ui-{suffix}");
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
    let ticket = json(response).await["login_ticket"]
        .as_str()
        .expect("login ticket")
        .to_owned();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"login_ticket": ticket}).to_string(),
                ))
                .expect("TOTP setup request"),
        )
        .await
        .expect("TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json(response).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "login_ticket": ticket,
                        "code": totp.generate_current().expect("TOTP code")
                    })
                    .to_string(),
                ))
                .expect("TOTP confirmation request"),
        )
        .await
        .expect("TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_header = cookies(&response);
    let csrf_token = csrf(&cookie_header).to_owned();
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

#[tokio::test]
async fn normal_user_can_create_only_two_owned_oauth_projects() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (cookies, csrf_token) = register_and_login(&router, &suffix).await;
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
        let created = json(response).await;
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
    assert_eq!(json(response).await["code"], "oauth_client_quota_exceeded");

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
    let clients = json(response).await;
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
    assert_eq!(json(response).await["authenticated"], true);
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
    let (owner_cookies, owner_csrf) = register_and_login(&router, &owner_suffix).await;
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
    let client_id = json(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();

    let other_suffix = Uuid::new_v4().simple().to_string();
    let (other_cookies, other_csrf) = register_and_login(&router, &other_suffix).await;
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
        json(response).await["items"]
            .as_array()
            .expect("other items")
            .is_empty()
    );

    for (method, suffix) in [
        ("PUT", ""),
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
    let (cookies, _) = register_and_login(&router, &suffix).await;
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
    assert_eq!(json(response).await["code"], "csrf_invalid");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(format!("ui-{suffix}@example.com"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn authorized_apps_are_user_scoped_and_consent_revoke_is_audited() {
    let (router, database, key_directory) = setup().await;
    let owner_suffix = Uuid::new_v4().simple().to_string();
    let (owner_cookies, owner_csrf) = register_and_login(&router, &owner_suffix).await;
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
    let client_id = json(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();

    let other_suffix = Uuid::new_v4().simple().to_string();
    let (other_cookies, _) = register_and_login(&router, &other_suffix).await;
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
    let apps = json(response).await;
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
    assert_eq!(json(response).await["code"], "csrf_invalid");

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

    let remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE oc.client_id = $1 AND c.user_id = $2",
    )
    .bind(&client_id)
    .bind(owner_id)
    .fetch_one(&database)
    .await
    .expect("owner consent count");
    assert_eq!(remaining, 0);
    let other_remaining: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE oc.client_id = $1 AND c.user_id = $2",
    )
    .bind(&client_id)
    .bind(other_id)
    .fetch_one(&database)
    .await
    .expect("other consent count");
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
        json(response).await["items"]
            .as_array()
            .expect("other items")
            .len(),
        1
    );

    chenxing_auth::sqlx::query(
        "DELETE FROM audit_events WHERE action = 'consent_revoke' AND resource_id = $1",
    )
    .bind(&client_id)
    .execute(&database)
    .await
    .expect("cleanup audit");
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
    let (cookies, csrf_token) = register_and_login(&router, &suffix).await;
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
    let client_id = json(response).await["client_id"]
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
    let decision = json(response).await;
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
    let clients = json(response).await;
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
    let (cookies, _) = register_and_login(&router, &suffix).await;
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
