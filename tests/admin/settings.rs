use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    config::Config,
    oauth::providers::secrets::SecretManager,
    sessions::{cookies, domain::Session, store::SessionStore},
    settings::{SettingsService, SmtpPasswordAction, SmtpSettingUpdate},
    sqlx,
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::db_isolation;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_settings", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-admin-settings-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-settings-token".to_owned();
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

async fn browser_session(
    database: &chenxing_auth::sqlx::PgPool,
    redis_url: &str,
    user_id: i64,
) -> (String, String) {
    let redis = redis::Client::open(redis_url).expect("session Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::session_cookie_name(false),
        session.token,
        cookies::csrf_cookie_name(false),
        session.csrf_token
    );
    (cookie, session.csrf_token)
}

#[tokio::test]
async fn owner_can_read_update_and_persist_registration_email_setting() {
    let (router, database, key_directory) = setup().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .body(Body::empty())
                .expect("settings request"),
        )
        .await
        .expect("settings response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json(response)
            .await
            .get("registration_email_from")
            .is_some()
    );

    let email = format!("registration-{}@example.com", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": "not-an-email"}).to_string(),
                ))
                .expect("invalid settings request"),
        )
        .await
        .expect("invalid settings response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_email");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("missing settings field request"),
        )
        .await
        .expect("missing settings field response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_request");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": email}).to_string(),
                ))
                .expect("unauthorized settings request"),
        )
        .await
        .expect("unauthorized settings response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": email}).to_string(),
                ))
                .expect("update settings request"),
        )
        .await
        .expect("update settings response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["registration_email_from"], email);

    let stored: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'registration_email_from'",
    )
    .fetch_one(&database)
    .await
    .expect("stored setting");
    assert_eq!(stored.as_deref(), Some(email.as_str()));

    let _ = std::fs::remove_dir_all(key_directory);
}

/// #414 回归：清除注册发件人必须对称地清掉镜像的 SMTP from，
/// 否则读取路径（SMTP from 优先）会持续命中残留旧地址。
#[tokio::test]
async fn clearing_registration_email_also_clears_mirrored_smtp_sender() {
    let (router, database, key_directory) = setup().await;
    let email = format!("registration-{}@example.com", Uuid::new_v4().simple());

    let smtp_from = || async {
        let raw: String = chenxing_auth::sqlx::query_scalar(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'smtp'",
        )
        .fetch_one(&database)
        .await
        .expect("smtp setting");
        serde_json::from_str::<Value>(&raw).expect("smtp JSON")["from_address"]
            .as_str()
            .expect("from_address string")
            .to_owned()
    };

    // 首次设置：SMTP from 被回填，两处互为镜像。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": email}).to_string(),
                ))
                .expect("set registration email request"),
        )
        .await
        .expect("set registration email response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["registration_email_from"], email);
    assert_eq!(smtp_from().await, email);

    // 清除：独立值与镜像的 SMTP from 必须一并清空。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": null}).to_string(),
                ))
                .expect("clear registration email request"),
        )
        .await
        .expect("clear registration email response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json(response).await["registration_email_from"].is_null());

    let stored: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'registration_email_from'",
    )
    .fetch_one(&database)
    .await
    .expect("stored setting");
    assert!(stored.is_none(), "independent value must be cleared");
    assert_eq!(smtp_from().await, "", "mirrored SMTP from must be cleared");

    // 清除后读取必须返回 null，而不是残留旧地址。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .body(Body::empty())
                .expect("read registration email request"),
        )
        .await
        .expect("read registration email response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json(response).await["registration_email_from"].is_null());

    let _ = std::fs::remove_dir_all(key_directory);
}

/// #482 regression: both email-setting writers must lock the two rows in the
/// same order before either path updates its first row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_smtp_and_registration_sender_updates_do_not_deadlock() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let database =
        db_isolation::isolated_pool_with_max_connections("admin_settings", &database_url, 4).await;
    let settings = SettingsService::new(
        database.clone(),
        SecretManager::from_key([0_u8; 32]),
        "localhost",
        "http://localhost",
    );
    sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('registration_email_from', NULL, NOW()), ('smtp', NULL, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = NULL, updated_at = EXCLUDED.updated_at",
    )
    .execute(&database)
    .await
    .expect("prepare existing email setting rows");
    sqlx::query(
        "CREATE FUNCTION gate_email_setting_update()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         BEGIN
             IF NEW.setting_key = 'registration_email_from' THEN
                 PERFORM pg_advisory_xact_lock(hashtext(TG_TABLE_SCHEMA::text), 1);
             ELSIF NEW.setting_key = 'smtp' THEN
                 PERFORM pg_advisory_xact_lock(hashtext(TG_TABLE_SCHEMA::text), 2);
             END IF;
             RETURN NEW;
         END;
         $$",
    )
    .execute(&database)
    .await
    .expect("create email setting gate function");
    sqlx::query(
        "CREATE TRIGGER gate_email_setting_update
         AFTER UPDATE ON app_settings
         FOR EACH ROW
         WHEN (NEW.setting_key IN ('registration_email_from', 'smtp'))
         EXECUTE FUNCTION gate_email_setting_update()",
    )
    .execute(&database)
    .await
    .expect("create email setting gate trigger");

    let mut gate_connection = database.acquire().await.expect("gate connection");
    let mut observer_connection = database.acquire().await.expect("observer connection");
    let mut first_service_connection = database.acquire().await.expect("first service connection");
    let mut second_service_connection =
        database.acquire().await.expect("second service connection");
    let application_name = format!("issue-482-{}", Uuid::new_v4().simple());
    let _: String = sqlx::query_scalar("SELECT set_config('application_name', $1, false)")
        .bind(&application_name)
        .fetch_one(&mut *first_service_connection)
        .await
        .expect("mark first service connection");
    let _: String = sqlx::query_scalar("SELECT set_config('application_name', $1, false)")
        .bind(&application_name)
        .fetch_one(&mut *second_service_connection)
        .await
        .expect("mark second service connection");
    for gate in [1_i32, 2_i32] {
        sqlx::query("SELECT pg_advisory_lock(hashtext(current_schema()::text), $1)")
            .bind(gate)
            .execute(&mut *gate_connection)
            .await
            .expect("hold email setting gate");
    }
    drop(first_service_connection);
    drop(second_service_connection);

    let smtp_email = format!("smtp-{}@example.com", Uuid::new_v4().simple());
    let smtp_from = format!("SMTP <{smtp_email}>");
    let registration_email = format!("registration-{}@example.com", Uuid::new_v4().simple());
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let smtp_request = {
        let barrier = barrier.clone();
        let settings = settings.clone();
        let smtp_email = smtp_email.clone();
        let smtp_from = smtp_from.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            settings
                .set_smtp(SmtpSettingUpdate {
                    host: "smtp.example.com".to_owned(),
                    port: 587,
                    username: smtp_email,
                    from_address: smtp_from,
                    ssl_enabled: true,
                    force_auth_login: false,
                    password_action: Some(SmtpPasswordAction::Keep),
                    password: None,
                })
                .await
        })
    };
    let registration_request = {
        let barrier = barrier.clone();
        let settings = settings.clone();
        let registration_email = registration_email.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            settings
                .set_registration_email_from(Some(registration_email))
                .await
        })
    };

    let gate_waiters = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked_writers: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)
                 FROM pg_stat_activity
                 WHERE application_name = $1
                   AND state = 'active'
                   AND wait_event_type = 'Lock'",
            )
            .bind(&application_name)
            .fetch_one(&mut *observer_connection)
            .await
            .expect("observe blocked email setting writers");
            if blocked_writers == 2 {
                break sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)
                     FROM pg_locks AS locks
                     JOIN pg_stat_activity AS activity ON activity.pid = locks.pid
                     WHERE activity.application_name = $1
                       AND locks.locktype = 'advisory'
                       AND NOT locks.granted",
                )
                .bind(&application_name)
                .fetch_one(&mut *observer_connection)
                .await
                .expect("count blocked email setting gates");
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both email setting writers must reach a controlled lock wait");

    for gate in [1_i32, 2_i32] {
        let unlocked: bool =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtext(current_schema()::text), $1)")
                .bind(gate)
                .fetch_one(&mut *gate_connection)
                .await
                .expect("release email setting gate");
        assert!(unlocked, "email setting gate {gate} must be held");
    }

    let (smtp_result, registration_result) =
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (smtp_result, registration_result) =
                tokio::join!(smtp_request, registration_request);
            (
                smtp_result.expect("join concurrent SMTP update"),
                registration_result.expect("join concurrent registration sender update"),
            )
        })
        .await
        .expect("concurrent email setting updates must not hang");
    assert_eq!(
        gate_waiters, 1,
        "only the transaction holding both setting rows may reach an UPDATE gate"
    );
    let (smtp_setting, password_action) = smtp_result.expect("concurrent SMTP update must succeed");
    assert_eq!(smtp_setting.from_address, smtp_from);
    assert_eq!(password_action, SmtpPasswordAction::Keep);
    assert_eq!(
        registration_result
            .expect("concurrent registration sender update must succeed")
            .as_deref(),
        Some(registration_email.as_str())
    );

    let stored_registration: Option<String> = sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'registration_email_from'",
    )
    .fetch_one(&database)
    .await
    .expect("stored registration sender");
    let stored_smtp: String =
        sqlx::query_scalar("SELECT setting_value FROM app_settings WHERE setting_key = 'smtp'")
            .fetch_one(&database)
            .await
            .expect("stored smtp setting");
    let stored_smtp: Value = serde_json::from_str(&stored_smtp).expect("stored smtp JSON");
    assert_eq!(stored_smtp["host"], "smtp.example.com");
    assert_eq!(stored_smtp["port"], 587);
    assert_eq!(stored_smtp["username"], smtp_email);
    assert_eq!(stored_smtp["ssl_enabled"].as_bool(), Some(true));
    assert_eq!(stored_smtp["force_auth_login"].as_bool(), Some(false));
    assert!(stored_smtp.get("password_ciphertext").is_none());
    let stored_smtp_from = stored_smtp["from_address"]
        .as_str()
        .expect("stored SMTP from address");

    let smtp_committed_last = stored_registration.as_deref() == Some(smtp_email.as_str())
        && stored_smtp_from == smtp_from.as_str();
    let registration_committed_last = stored_registration.as_deref()
        == Some(registration_email.as_str())
        && stored_smtp_from == smtp_from.as_str();
    assert!(
        smtp_committed_last || registration_committed_last,
        "final settings must match a legal serial order: registration={stored_registration:?}, smtp_from={stored_smtp_from}"
    );
}

#[tokio::test]
async fn session_authenticated_setting_mutation_records_user_actor() {
    let (router, database, key_directory) = setup().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let username = format!("settings-owner-{}", Uuid::new_v4().simple());
    let email = format!("{username}@example.com");
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())
         RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .fetch_one(&database)
    .await
    .expect("owner user");
    let (cookie, csrf) = browser_session(&database, &redis_url, user_id).await;
    let registration_email = format!("sender-{}@example.com", Uuid::new_v4().simple());

    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": registration_email}).to_string(),
                ))
                .expect("session setting request"),
        )
        .await
        .expect("session setting response");
    assert_eq!(response.status(), StatusCode::OK);

    let actor: Option<i64> = sqlx::query_scalar(
        "SELECT actor_user_id FROM audit_events
         WHERE action = 'registration_email_update' AND resource_id = $1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(chenxing_auth::settings::REGISTRATION_EMAIL_FROM_KEY)
    .fetch_one(&database)
    .await
    .expect("registration audit event");
    assert_eq!(actor, Some(user_id));

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup owner");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn setting_write_rolls_back_when_its_audit_insert_fails() {
    let (router, database, key_directory) = setup().await;
    sqlx::query(
        "CREATE FUNCTION reject_setting_audit_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             RAISE EXCEPTION 'injected audit failure';
         END;
         $$",
    )
    .execute(&database)
    .await
    .expect("audit failure function");
    sqlx::query(
        "CREATE TRIGGER reject_setting_audit_for_test
         BEFORE INSERT ON audit_events
         FOR EACH ROW EXECUTE FUNCTION reject_setting_audit_for_test()",
    )
    .execute(&database)
    .await
    .expect("audit failure trigger");

    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "registration_email_from": "must-rollback@example.com"
                    })
                    .to_string(),
                ))
                .expect("setting request with injected audit failure"),
        )
        .await
        .expect("setting response with injected audit failure");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let stored: Option<String> = sqlx::query_scalar(
        "SELECT setting_value FROM app_settings
         WHERE setting_key = 'registration_email_from'",
    )
    .fetch_optional(&database)
    .await
    .expect("rolled back setting query")
    .flatten();
    assert!(
        stored.is_none(),
        "setting must roll back with its audit row"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn key_rotation_keeps_a_durable_intent_when_outcome_audit_fails() {
    let (router, database, key_directory) = setup().await;
    sqlx::query(
        "CREATE FUNCTION reject_key_outcome_audit_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.resource_type = 'signing_key'
                AND NEW.metadata ->> 'phase' = 'outcome' THEN
                 RAISE EXCEPTION 'injected key outcome audit failure';
             END IF;
             RETURN NEW;
         END;
         $$",
    )
    .execute(&database)
    .await
    .expect("key outcome failure function");
    sqlx::query(
        "CREATE TRIGGER reject_key_outcome_audit_for_test
         BEFORE INSERT ON audit_events
         FOR EACH ROW EXECUTE FUNCTION reject_key_outcome_audit_for_test()",
    )
    .execute(&database)
    .await
    .expect("key outcome failure trigger");

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/keys/rotate")
                .header("authorization", "Bearer admin-settings-token")
                .body(Body::empty())
                .expect("key rotation request"),
        )
        .await
        .expect("key rotation response");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = json(response).await;
    assert!(
        payload["key_id"]
            .as_str()
            .is_some_and(|key_id| !key_id.is_empty())
    );

    let (actor_type, actor_user_id, request_id, metadata): (String, Option<i64>, String, Value) =
        sqlx::query_as(
            "SELECT actor_type, actor_user_id, metadata ->> 'request_id', metadata
         FROM audit_events
         WHERE action = 'signing_key_rotate'
           AND resource_type = 'signing_key'
           AND metadata ->> 'phase' = 'intent'
         ORDER BY id DESC
         LIMIT 1",
        )
        .fetch_one(&database)
        .await
        .expect("durable key rotation intent");
    assert!(!actor_type.is_empty());
    assert_eq!(actor_user_id, None);
    assert!(!request_id.is_empty());
    assert_eq!(metadata["result"], "pending");
    assert!(metadata.get("private_key").is_none());

    let outcome_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE action = 'signing_key_rotate'
           AND metadata ->> 'request_id' = $1
           AND metadata ->> 'phase' = 'outcome'",
    )
    .bind(request_id)
    .fetch_one(&database)
    .await
    .expect("key outcome count");
    assert_eq!(outcome_count, 0, "failed outcome leaves the intent pending");

    let _ = std::fs::remove_dir_all(key_directory);
}
