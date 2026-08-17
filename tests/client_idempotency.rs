use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, oauth::refresh::RefreshToken, state::AppState};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

async fn setup() -> (
    AppState,
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("client_idempotency", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("client-idempotency");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "idempotency-admin-token".to_owned();
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    (state.clone(), api::router(state), database, key_directory)
}

fn client_body(name: &str) -> String {
    serde_json::json!({
        "client_name": name,
        "redirect_uris": ["https://idempotency.example/callback"],
        "scopes": ["openid", "profile"]
    })
    .to_string()
}

fn create_request(key: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/admin/clients")
        .header("authorization", "Bearer idempotency-admin-token")
        .header("idempotency-key", key)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("create client request")
}

fn rotate_request(client_id: &str, key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/clients/{client_id}/rotate-secret"))
        .header("authorization", "Bearer idempotency-admin-token")
        .header("idempotency-key", key)
        .body(Body::empty())
        .expect("rotate client secret request")
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

#[tokio::test]
async fn create_retry_replays_the_same_secret_without_duplicate_mutation_or_audit() {
    let (_state, router, database, key_directory) = setup().await;
    let key = format!("create-{}", Uuid::new_v4().simple());
    let body = client_body("Idempotent create");

    let first = router
        .clone()
        .oneshot(create_request(&key, body.clone()))
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::CREATED);
    let first = json(first).await;

    let retry = router
        .clone()
        .oneshot(create_request(&key, body))
        .await
        .expect("retry response");
    assert_eq!(retry.status(), StatusCode::CREATED);
    let retry = json(retry).await;

    assert_eq!(retry["id"], first["id"]);
    assert_eq!(retry["client_id"], first["client_id"]);
    assert_eq!(retry["client_secret"], first["client_secret"]);

    let client_id = first["client_id"].as_str().expect("client id");
    let client_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(&database)
    .await
    .expect("client count");
    assert_eq!(client_count, 1);
    let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_create' AND resource_id = $1",
    )
    .bind(client_id)
    .fetch_one(&database)
    .await
    .expect("audit count");
    assert_eq!(audit_count, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_create_requests_with_the_same_key_serialize_to_one_result() {
    let (_state, router, database, key_directory) = setup().await;
    let key = format!("concurrent-create-{}", Uuid::new_v4().simple());
    let body = client_body("Concurrent create");
    let first = router.clone().oneshot(create_request(&key, body.clone()));
    let second = router.clone().oneshot(create_request(&key, body));
    let (first, second) = tokio::join!(first, second);
    let first = json(first.expect("first response")).await;
    let second = json(second.expect("second response")).await;

    assert_eq!(first["client_id"], second["client_id"]);
    assert_eq!(first["client_secret"], second["client_secret"]);
    let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_create' AND resource_id = $1",
    )
    .bind(first["client_id"].as_str().expect("client id"))
    .fetch_one(&database)
    .await
    .expect("audit count");
    assert_eq!(audit_count, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn changed_create_request_with_the_same_key_conflicts() {
    let (_state, router, database, key_directory) = setup().await;
    let key = format!("create-conflict-{}", Uuid::new_v4().simple());

    let first = router
        .clone()
        .oneshot(create_request(&key, client_body("First request")))
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::CREATED);

    let conflict = router
        .clone()
        .oneshot(create_request(&key, client_body("Changed request")))
        .await
        .expect("conflict response");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(json(conflict).await["code"], "idempotency_conflict");

    let client_count: i64 = chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(&database)
        .await
        .expect("client count");
    assert_eq!(client_count, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn rotation_retry_replays_the_same_secret_and_rotates_once() {
    let (state, router, database, key_directory) = setup().await;
    let create = router
        .clone()
        .oneshot(create_request(
            &format!("create-{}", Uuid::new_v4().simple()),
            client_body("Rotation target"),
        ))
        .await
        .expect("create response");
    assert_eq!(create.status(), StatusCode::CREATED);
    let created = json(create).await;
    let client_id = created["client_id"].as_str().expect("client id");
    let original_secret = created["client_secret"].as_str().expect("original secret");
    let key = format!("rotate-{}", Uuid::new_v4().simple());

    let first = router
        .clone()
        .oneshot(rotate_request(client_id, &key))
        .await
        .expect("first rotation response");
    assert_eq!(first.status(), StatusCode::OK);
    let first = json(first).await;

    // A retry must replay the committed response without repeating lifecycle
    // side effects. Leave a token behind after the first rotation so a replay
    // that calls revoke_client_tokens again is observable.
    let now = OffsetDateTime::now_utc();
    let sentinel = RefreshToken {
        value: format!("sentinel-{}", Uuid::new_v4().simple()),
        client_id: client_id.to_owned(),
        user_id: "idempotency-test-user".to_owned(),
        scopes: vec!["openid".to_owned()],
        created_at: now,
        expires_at: now + Duration::hours(1),
        revoked_at: None,
        issued_at: Some(now),
        family_id: format!("family-{}", Uuid::new_v4().simple()),
        client_secret_version: Some(1),
        session_epoch: Some(0),
        issuer_generation: Some(0),
        cas_revision: 0,
    };
    let sentinel_value = sentinel.value.clone();
    state
        .refresh_tokens
        .save(&sentinel)
        .await
        .expect("save sentinel refresh token");

    let retry = router
        .clone()
        .oneshot(rotate_request(client_id, &key))
        .await
        .expect("retry rotation response");
    assert_eq!(retry.status(), StatusCode::OK);
    let retry = json(retry).await;
    assert_eq!(retry["client_secret"], first["client_secret"]);
    assert_ne!(retry["client_secret"], original_secret);
    assert!(
        state
            .refresh_tokens
            .find(&sentinel_value)
            .await
            .expect("find sentinel refresh token")
            .is_some(),
        "idempotent rotation replay must not revoke refresh tokens again"
    );
    state
        .refresh_tokens
        .remove(&sentinel_value)
        .await
        .expect("remove sentinel refresh token");

    let version: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT client_secret_version FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(&database)
    .await
    .expect("secret version");
    assert_eq!(version, 1);
    let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_secret_rotate' AND resource_id = $1",
    )
    .bind(client_id)
    .fetch_one(&database)
    .await
    .expect("rotation audit count");
    assert_eq!(audit_count, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn audit_failure_rolls_back_the_client_and_idempotency_result() {
    let (_state, router, database, key_directory) = setup().await;
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION reject_client_create_audit() RETURNS trigger AS $$
         BEGIN
           IF NEW.action = 'client_create' THEN
             RAISE EXCEPTION 'injected client audit failure';
           END IF;
           RETURN NEW;
         END;
         $$ LANGUAGE plpgsql",
    )
    .execute(&database)
    .await
    .expect("create failure function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER reject_client_create_audit
         BEFORE INSERT ON audit_events
         FOR EACH ROW EXECUTE FUNCTION reject_client_create_audit()",
    )
    .execute(&database)
    .await
    .expect("create failure trigger");

    let key = format!("audit-failure-{}", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(create_request(&key, client_body("Audit rollback")))
        .await
        .expect("failed create response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(response).await["code"], "audit_unavailable");

    let client_count: i64 = chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(&database)
        .await
        .expect("client count");
    assert_eq!(client_count, 0);
    let idempotency_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM client_operation_idempotency")
            .fetch_one(&database)
            .await
            .expect("idempotency count");
    assert_eq!(idempotency_count, 0);

    chenxing_auth::sqlx::query("DROP TRIGGER reject_client_create_audit ON audit_events")
        .execute(&database)
        .await
        .expect("drop failure trigger");
    let retry = router
        .oneshot(create_request(&key, client_body("Audit rollback")))
        .await
        .expect("retry response");
    assert_eq!(retry.status(), StatusCode::CREATED);

    let _ = std::fs::remove_dir_all(key_directory);
}
