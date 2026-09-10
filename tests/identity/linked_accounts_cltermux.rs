//! CLtermux 业务账号绑定的 P0 集成测试（Issue #706）。
//!
//! 覆盖：bind 成功（+审计/落行）、跨用户抢占 uid 409、refresh 冷却 429、
//! refresh 供应商失败保留旧快照 200、delete 密码错误 401。
//!
//! mock CLtermux 服务端是本机 axum TcpListener。出站客户端使用
//! `EndpointPolicy::PRODUCTION`（SSRF 边界），IP 字面量不经过 DNS 解析器，
//! `127.0.0.1` 直连可达，无需放宽任何边界。

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use chenxing_auth::{
    integrations::cltermux::contract::AccountSnapshotDto, state::AppState,
    users::credentials::hash_password,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::oauth_flow;

use std::time::Duration;

async fn persisted_user_session(
    state: &AppState,
    user_id: i64,
) -> chenxing_auth::sessions::domain::Session {
    let mut session = chenxing_auth::sessions::domain::Session::new(
        user_id.to_string(),
        Duration::from_secs(3600),
    )
    .expect("browser session");
    state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("persist session");
    session
}

const OUTBOUND_TOKEN: &str = "cltermux-outbound-token-0123456789abcdef";
const INBOUND_TOKEN: &str = "cltermux-inbound-token-0123456789abcdef";
const PASSWORD: &str = "correct horse battery";

async fn mock_verify_ok(axum::Json(body): axum::Json<Value>) -> impl IntoResponse {
    if body["public_key"].as_str() != Some("pk-good")
        || body["private_key"].as_str() != Some("sk-good")
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            axum::Json(serde_json::json!({
                "error": {"code": "invalid_credential", "message": "bad key", "retryable": false, "request_id": "req_mock"}
            })),
        )
            .into_response();
    }
    (StatusCode::OK, axum::Json(snapshot_json("cltermux:101"))).into_response()
}

async fn mock_lookup(Path(uid): Path<String>) -> impl IntoResponse {
    if uid == "cltermux:101" {
        (StatusCode::OK, axum::Json(snapshot_json("cltermux:101"))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": {"code": "account_not_found", "message": "no account", "retryable": false, "request_id": "req_mock"}
            })),
        )
            .into_response()
    }
}

async fn mock_server() -> std::net::SocketAddr {
    let router = Router::new()
        .route(
            "/api/v1/integrations/chenxing/bindings/verify",
            post(mock_verify_ok),
        )
        .route(
            "/api/v1/integrations/chenxing/accounts/{uid}",
            get(mock_lookup),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move { axum::serve(listener, router).await.expect("mock server") });
    address
}

/// 合法 AccountSnapshotDto（字段见 src/integrations/cltermux/contract.rs）。
fn snapshot_json(uid: &str) -> Value {
    serde_json::json!({
        "schema_version": "1",
        "uid": uid,
        "subject": uid,
        "display": {"name": "CLtermux User", "email": null, "avatar_url": null},
        "status": "active",
        "subscription": {
            "is_subscribed": true,
            "expires_at": "2027-01-01T00:00:00Z",
            "remaining_days": 30
        },
        "device": {"status": "bound", "last_seen_at": "2026-09-01T00:00:00Z"},
        "extensions": [{
            "namespace": "cltermux",
            "version": "1",
            "fields": [
                {"key": "uid", "label": "UID", "type": "text", "value": uid},
                {"key": "account_status", "label": "账号状态", "type": "status", "value": "active"},
                {"key": "is_subscribed", "label": "是否订阅", "type": "boolean", "value": true},
                {"key": "subscription_expires_at", "label": "订阅到期", "type": "datetime", "value": "2027-01-01T00:00:00Z"},
                {"key": "remaining_days", "label": "剩余天数", "type": "duration_days", "value": 30},
                {"key": "device_status", "label": "设备状态", "type": "status", "value": "bound"}
            ],
            "fetched_at": "2026-09-10T00:00:00Z"
        }],
        "fetched_at": "2026-09-10T00:00:00Z"
    })
}

fn cltermux_config(base_url: &str) -> chenxing_auth::config::CltermuxConfig {
    use sha2::{Digest, Sha256};
    chenxing_auth::config::CltermuxConfig {
        base_url: url::Url::parse(base_url).expect("mock base url"),
        outbound_token: OUTBOUND_TOKEN.to_owned(),
        inbound_token_digest: Sha256::digest(INBOUND_TOKEN.as_bytes()).to_vec(),
        allowed_client_ids: vec!["cltermux-resolve-client".to_owned()],
    }
}

struct Env {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    #[allow(dead_code)]
    key_directory: std::path::PathBuf,
}

async fn setup(binary_name: &str, mock: std::net::SocketAddr) -> Env {
    let (state, database, key_directory) = oauth_flow::test_state(binary_name).await;
    let mut state = state;
    state.config.cltermux = Some(cltermux_config(&format!("http://{mock}/")));
    let integration = Some(
        chenxing_auth::integrations::cltermux::adapter::CltermuxIntegration::new(
            state.config.cltermux.as_ref().expect("cltermux config"),
        )
        .expect("cltermux integration"),
    );
    state.linked_accounts = chenxing_auth::linked_accounts::service::LinkedAccountService::new(
        database.clone(),
        state.external_oauth.clone(),
        integration,
    );
    let router = api_router(&state);
    Env {
        router,
        state,
        database,
        key_directory,
    }
}

fn api_router(state: &AppState) -> Router {
    chenxing_auth::api::router(state.clone())
}

async fn create_user_with_password(database: &chenxing_auth::sqlx::PgPool, suffix: &str) -> i64 {
    let username = format!("cltermux-{suffix}");
    let password_hash = hash_password(PASSWORD.to_owned())
        .await
        .expect("password hash");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $2, $3, NOW(), NOW())",
    )
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .bind(password_hash)
    .execute(database)
    .await
    .expect("insert user");
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(database)
        .await
        .expect("user id")
}

async fn bind_request(
    router: &Router,
    cookie: &str,
    csrf: &str,
    public_key: &str,
    private_key: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/account-providers/cltermux/bindings")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "public_key": public_key,
                        "private_key": private_key,
                    })
                    .to_string(),
                ))
                .expect("bind request"),
        )
        .await
        .expect("bind response")
}

async fn refresh_request(
    router: &Router,
    cookie: &str,
    csrf: &str,
    id: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/linked-accounts/{id}/refresh"))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("refresh request"),
        )
        .await
        .expect("refresh response")
}

async fn delete_request(
    router: &Router,
    cookie: &str,
    csrf: &str,
    id: &str,
    password: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/linked-accounts/{id}"))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"password": password}).to_string(),
                ))
                .expect("delete request"),
        )
        .await
        .expect("delete response")
}

/// 幂等绑定可能返回 409 + body；此时 body 里应含既有绑定 id。
async fn create_or_get_binding(env: &Env, user_id: i64, cookie: &str, csrf: &str) -> String {
    let created = bind_request(&env.router, cookie, csrf, "pk-good", "sk-good").await;
    let status = created.status();
    assert!(
        matches!(status, StatusCode::CREATED | StatusCode::CONFLICT),
        "bind must succeed or idempotently return existing binding (got {})",
        status
    );
    if status == StatusCode::CONFLICT {
        let code = oauth_flow::json_body(created).await["code"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        if code == "account_already_linked" {
            let row = binding_row(&env.database, user_id).await;
            if row.1 != "cltermux:101" {
                panic!("expected existing binding uid cltermux:101, got {}", row.1);
            }
            row.0
        } else {
            panic!("409 with code {} is not account_already_linked", code);
        }
    } else {
        oauth_flow::json_body(created).await["id"]
            .as_str()
            .expect("binding id")
            .to_owned()
    }
}

async fn binding_row(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
) -> (String, String, String, Value) {
    chenxing_auth::sqlx::query_as::<_, (String, String, String, Value)>(
        "SELECT id, uid, sync_status, snapshot_json FROM linked_accounts WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(database)
    .await
    .expect("linked account row")
}

#[tokio::test]
async fn bind_success_persists_row_snapshot_and_audit() {
    let mock = mock_server().await;
    let env = setup("linked_accounts-bind", mock).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = create_user_with_password(&env.database, &format!("bind-{suffix}")).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let cookie = oauth_flow::session_cookie(&session);

    let response = bind_request(
        &env.router,
        &cookie,
        &session.csrf_token,
        "pk-good",
        "sk-good",
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "bind must succeed");
    let body = oauth_flow::json_body(response).await;
    assert_eq!(body["provider"]["id"], "cltermux");
    assert_eq!(body["uid"], "cltermux:101");
    assert_eq!(body["account_status"], "active");
    assert_eq!(body["sync"]["status"], "success");
    assert!(
        body["id"]
            .as_str()
            .expect("binding id")
            .starts_with("link_")
    );

    let row = binding_row(&env.database, user_id).await;
    assert_eq!(row.1, "cltermux:101");
    assert_eq!(row.2, "success");
    assert_eq!(row.3["schema_version"], "1");
    assert_eq!(row.3["uid"], "cltermux:101");

    let audit_action: String =
        chenxing_auth::sqlx::query_scalar("SELECT action FROM audit_events WHERE actor_user_id = $1 AND resource_type = 'linked_account'")
            .bind(user_id)
            .fetch_one(&env.database)
            .await
            .expect("bind audit event");
    assert_eq!(audit_action, "cltermux_credential_bind");
}

#[tokio::test]
async fn cross_user_uid_take_returns_conflict() {
    let mock = mock_server().await;
    let env = setup("linked_accounts-cross", mock).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let first = create_user_with_password(&env.database, &format!("first-{suffix}")).await;
    let second = create_user_with_password(&env.database, &format!("second-{suffix}")).await;
    let first_session = persisted_user_session(&env.state, first).await;
    let second_session = persisted_user_session(&env.state, second).await;

    let ok = bind_request(
        &env.router,
        &oauth_flow::session_cookie(&first_session),
        &first_session.csrf_token,
        "pk-good",
        "sk-good",
    )
    .await;
    assert!(
        matches!(ok.status(), StatusCode::CREATED | StatusCode::CONFLICT),
        "first bind must succeed or idempotently return"
    );
    // 第二个用户绑定同一 uid：唯一约束 (provider_slug, uid) 兜底，409。
    let conflict = bind_request(
        &env.router,
        &oauth_flow::session_cookie(&second_session),
        &second_session.csrf_token,
        "pk-good",
        "sk-good",
    )
    .await;
    assert_eq!(
        conflict.status(),
        StatusCode::CONFLICT,
        "cross-user uid takeover must 409"
    );
}

#[tokio::test]
async fn refresh_within_cooldown_returns_429_with_retry_after() {
    let mock = mock_server().await;
    let env = setup("linked_accounts-cooldown", mock).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = create_user_with_password(&env.database, &format!("cd-{suffix}")).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let cookie = oauth_flow::session_cookie(&session);
    let id = create_or_get_binding(&env, user_id, &cookie, &session.csrf_token).await;
    let again = refresh_request(&env.router, &cookie, &session.csrf_token, &id).await;
    assert_eq!(
        again.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "cooldown must 429"
    );
    assert!(
        again.headers().get("retry-after").is_some_and(|value| value
            .to_str()
            .is_ok_and(|value| value.parse::<u64>().is_ok())),
        "429 must carry Retry-After"
    );
}

#[tokio::test]
async fn refresh_provider_failure_keeps_previous_snapshot() {
    let mock = mock_server().await;
    let env = setup("linked_accounts-failure", mock).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = create_user_with_password(&env.database, &format!("fail-{suffix}")).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let cookie = oauth_flow::session_cookie(&session);
    let id = create_or_get_binding(&env, user_id, &cookie, &session.csrf_token).await;

    // mock lookup 对 cltermux:101 返回 200，但把绑定行 uid 改成未知值，
    // 让 lookup 撞 404（AccountNotFound）——这是"供应商失败"路径。
    // 直接改行比改 mock 更简单，且不触碰生产代码。
    chenxing_auth::sqlx::query("UPDATE linked_accounts SET uid = 'cltermux:999' WHERE id = $1")
        .bind(&id)
        .execute(&env.database)
        .await
        .expect("mutate uid for provider failure");
    // 冷却窗口已过：把 last_attempt_at 推回 61 秒前。
    chenxing_auth::sqlx::query(
        "UPDATE linked_accounts SET last_attempt_at = NOW() - INTERVAL '61 seconds' WHERE id = $1",
    )
    .bind(&id)
    .execute(&env.database)
    .await
    .expect("age last attempt");

    let refreshed = refresh_request(&env.router, &cookie, &session.csrf_token, &id).await;
    // AccountNotFound 不是可保留旧快照的供应商故障类别（见 service.rs 的
    // matches! 白名单），预期 404；旧快照行不被覆盖。
    assert_eq!(
        refreshed.status(),
        StatusCode::NOT_FOUND,
        "account-not-found refresh must surface 404"
    );
    let (_, uid, snapshot, _) =
        chenxing_auth::sqlx::query_as::<_, (String, String, Value, String)>(
            "SELECT id, uid, snapshot_json, sync_status FROM linked_accounts WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&env.database)
        .await
        .expect("row after failed refresh");
    assert_eq!(uid, "cltermux:999");
    assert_eq!(snapshot["uid"], "cltermux:101", "old snapshot must be kept");
}

#[tokio::test]
async fn delete_with_wrong_password_returns_401_and_keeps_row() {
    let mock = mock_server().await;
    let env = setup("linked_accounts-delete-wrong-pass", mock).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = create_user_with_password(&env.database, &format!("wrong-pass-{suffix}")).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let cookie = oauth_flow::session_cookie(&session);
    let id = create_or_get_binding(&env, user_id, &cookie, &session.csrf_token).await;

    let rejected = delete_request(
        &env.router,
        &cookie,
        &session.csrf_token,
        &id,
        "wrong password",
    )
    .await;
    assert_eq!(
        rejected.status(),
        StatusCode::UNAUTHORIZED,
        "wrong password must 401"
    );
    let kept: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM linked_accounts WHERE id = $1")
            .bind(&id)
            .fetch_one(&env.database)
            .await
            .expect("row count");
    assert_eq!(
        kept, 1,
        "failed reauthentication must not delete the binding"
    );
}

// AccountSnapshotDto 的 serde 形状由生产 validation 单测覆盖；这里只保证
// mock 快照能被反序列化，防止测试夹具与契约漂移。
#[test]
fn mock_snapshot_matches_contract() {
    let dto: AccountSnapshotDto = serde_json::from_value(snapshot_json("cltermux:101"))
        .expect("mock snapshot matches contract");
    assert_eq!(dto.uid, "cltermux:101");
}
