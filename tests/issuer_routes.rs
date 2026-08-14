use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use chenxing_auth::{api, config::Config, settings::IssuerRuntime, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

const ADMIN_TOKEN: &str = "issuer-routes-admin-token";

const ISSUER_DIAGNOSTIC_KEYS: &[&str] = &[
    "generation",
    "phase",
    "issuer_persisted",
    "persisted",
    "persisted_generation",
    "issuer_loaded",
    "loaded_generation",
];

async fn restricted_router(
    invalid: bool,
) -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("issuer_routes", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("issuer-routes");
    let mut config =
        Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
            .expect("config");
    config.issuer = None;
    config.cookie_secure = true;
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("restricted state");
    if invalid {
        state.issuer = IssuerRuntime::new_invalid(&state.config, 1);
    }
    (api::router(state), database, key_directory)
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON body")
}

async fn get_bootstrap_status(router: &Router) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("status request"),
        )
        .await
        .expect("status response");
    (response.status(), json_body(response).await)
}

async fn unknown_path_body(router: &Router) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/does-not-exist")
                .body(Body::empty())
                .expect("unknown path request"),
        )
        .await
        .expect("unknown path response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    json_body(response).await
}

fn assert_no_issuer_diagnostics(body: &Value) {
    for key in ISSUER_DIAGNOSTIC_KEYS {
        assert!(
            body.get(*key).is_none(),
            "anonymous bootstrap/status leaked {key}: {body}"
        );
    }
}

async fn insert_owner(database: &chenxing_auth::sqlx::PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())",
    )
    .bind(format!("issuer-owner-{suffix}"))
    .bind(format!("issuer-owner-{suffix}@example.com"))
    .execute(database)
    .await
    .expect("insert owner");
}

#[tokio::test]
async fn missing_issuer_keeps_health_and_spa_but_disables_application_routes() {
    let (router, _database, key_directory) = restricted_router(false).await;

    for path in ["/health/live", "/login"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("allowed request"),
            )
            .await
            .expect("allowed response");
        assert_eq!(response.status(), StatusCode::OK, "path={path}");
    }

    let (status, body) = get_bootstrap_status(&router).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["initialized"], false);
    assert_no_issuer_diagnostics(&body);

    for (method, path) in [
        (Method::POST, "/api/v1/auth/login"),
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/.well-known/jwks.json"),
        (Method::GET, "/oauth/authorize"),
    ] {
        let body = (path == "/api/v1/auth/login").then_some(Body::from("{}"));
        let mut request = Request::builder().method(method).uri(path);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(body.unwrap_or_else(Body::empty))
                    .expect("disabled request"),
            )
            .await
            .expect("disabled response");
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "path={path}"
        );
    }

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn issuer_gate_uses_oauth_envelope_only_for_registered_protocol_endpoints() {
    for invalid in [false, true] {
        let (router, _database, key_directory) = restricted_router(invalid).await;

        for (method, path) in [
            (Method::GET, "/oauth/authorize"),
            (Method::POST, "/oauth/token"),
            (Method::POST, "/oauth/revoke"),
            (Method::GET, "/oauth/userinfo"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("OAuth request"),
                )
                .await
                .expect("OAuth response");
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid={invalid}, path={path}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next()),
                Some("application/json"),
                "invalid={invalid}, path={path}"
            );
            let body: serde_json::Value = serde_json::from_slice(
                &to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("OAuth response body"),
            )
            .expect("OAuth response JSON");
            assert_eq!(body["error"], "temporarily_unavailable");
            assert!(body["error_description"].as_str().is_some());
            assert!(body.get("code").is_none());
            assert!(body.get("message").is_none());
        }

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/oauth/not-registered")
                    .body(Body::empty())
                    .expect("unknown OAuth path request"),
            )
            .await
            .expect("unknown OAuth path response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(key_directory);
    }
}

/// #440：匿名 bootstrap/status 不得把 Issuer 收敛内部状态当成初始化信号。
///
/// Owner 不存在时前端仍需要稳定的 `initialized: false`；Owner 存在时所有异常
/// 收敛状态必须与未知路径的 404 无法区分，不能恢复 initialized 预言机。
#[tokio::test]
async fn anonymous_status_hides_issuer_convergence_when_owner_is_absent() {
    for invalid in [false, true] {
        let (router, database, key_directory) = restricted_router(invalid).await;
        if !invalid {
            chenxing_auth::settings::issuer::initialize(&database, "https://auth.example.com")
                .await
                .expect("persist issuer without loading it");
        }

        let (status, body) = get_bootstrap_status(&router).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "uninitialized instance must keep the frontend bootstrap signal; invalid={invalid}"
        );
        assert_eq!(body["initialized"], false);
        assert_no_issuer_diagnostics(&body);

        let _ = std::fs::remove_dir_all(key_directory);
    }
}

#[tokio::test]
async fn anonymous_status_collapses_issuer_anomalies_once_owner_exists() {
    let hidden_bodies = {
        let mut bodies = Vec::new();
        for invalid in [false, true] {
            let (router, database, key_directory) = restricted_router(invalid).await;
            if !invalid {
                chenxing_auth::settings::issuer::initialize(&database, "https://auth.example.com")
                    .await
                    .expect("persist issuer without loading it");
            }
            insert_owner(&database).await;

            let (status, body) = get_bootstrap_status(&router).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "owner-present anomalies must not be distinguishable; invalid={invalid}"
            );
            assert_no_issuer_diagnostics(&body);
            assert_eq!(body, unknown_path_body(&router).await);
            bodies.push(body);
            let _ = std::fs::remove_dir_all(key_directory);
        }
        bodies
    };
    assert_eq!(
        hidden_bodies[0], hidden_bodies[1],
        "pending reload and invalid runtime must collapse to the same anonymous 404"
    );
}

#[tokio::test]
async fn manage_issuer_keeps_convergence_diagnostics() {
    let (router, database, key_directory) = restricted_router(false).await;
    chenxing_auth::settings::issuer::initialize(&database, "https://auth.example.com")
        .await
        .expect("persist issuer without loading it");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/issuer")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("issuer setting request"),
        )
        .await
        .expect("issuer setting response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["phase"], "awaiting_issuer");
    assert_eq!(body["persisted"]["value"], "https://auth.example.com");
    assert_eq!(body["persisted"]["generation"], 1);
    assert!(body["loaded"].is_null());

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn manage_issuer_reports_invalid_runtime_phase() {
    let (router, _database, key_directory) = restricted_router(true).await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/issuer")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("issuer setting request"),
        )
        .await
        .expect("issuer setting response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["phase"], "issuer_invalid");
    assert!(body.get("persisted").is_some());
    assert!(body.get("loaded").is_some());

    let _ = std::fs::remove_dir_all(key_directory);
}
