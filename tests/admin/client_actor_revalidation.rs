//! Issue #728: admin Client and App Link writes recheck the actor session
//! inside the mutation transaction.
//!
//! Single-session revoke sets `user_sessions.revoked_at` without advancing
//! `users.session_epoch`. The write holds that user row, the session is revoked
//! while the transaction waits, and the commit must not change `oauth_clients`
//! or hand a new secret back.

use std::time::Duration;

use chenxing_auth::{
    audit::{AuditAction, AuditEvent},
    clients::{
        domain::ClientRegistrationInput, idempotency::IdempotencyKey, service::ClientServiceError,
    },
    sessions::domain::Session,
    users::{ManagementActorCredential, ManagementActorValidationError},
};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

const FINGERPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

type TestEnv = crate::harness::Harness;

async fn setup() -> TestEnv {
    crate::harness::HarnessBuilder::new("admin_client_actor_revalidation")
        .admin_token("flow-admin-token")
        .max_connections(16)
        .build()
        .await
}

async fn seed_owner(database: &chenxing_auth::sqlx::PgPool, name: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, role, status)
         VALUES ($1, $2, lower($2), 'not-a-real-hash', 'owner', 'active')
         RETURNING id",
    )
    .bind(name)
    .bind(format!("{name}@example.com"))
    .fetch_one(database)
    .await
    .expect("seed owner")
}

async fn save_session(env: &TestEnv, user_id: i64) -> Session {
    let mut session =
        Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("session");
    env.state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("save session");
    session
}

fn credential(user_id: i64, session: &Session) -> ManagementActorCredential {
    ManagementActorCredential::UserSession {
        user_id,
        session_id: session.id,
        generation: session
            .credential_generation()
            .expect("persisted session generation"),
    }
}

fn registration(name: &str) -> ClientRegistrationInput {
    ClientRegistrationInput {
        client_name: name.to_owned(),
        redirect_uris: vec!["https://app.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        logo_uri: None,
        client_uri: None,
        description: None,
    }
}

fn audit(actor_id: i64, action: AuditAction, resource_id: Option<String>) -> AuditEvent {
    AuditEvent::new(
        "user".to_owned(),
        Some(actor_id.to_string()),
        action,
        "oauth_client".to_owned(),
        resource_id,
        serde_json::json!({"result": "success"}),
    )
}

struct ClientSnapshot {
    name: String,
    version: i64,
    status: String,
    has_link: bool,
}

async fn snapshot(database: &chenxing_auth::sqlx::PgPool, client_id: &str) -> ClientSnapshot {
    let (name, version, status, has_link): (String, i64, String, bool) =
        chenxing_auth::sqlx::query_as(
            "SELECT client_name, client_secret_version, status, android_asset_link IS NOT NULL
         FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_one(database)
        .await
        .expect("client snapshot");
    ClientSnapshot {
        name,
        version,
        status,
        has_link,
    }
}

async fn client_count(database: &chenxing_auth::sqlx::PgPool) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(database)
        .await
        .expect("client count")
}

async fn security_audit_count(database: &chenxing_auth::sqlx::PgPool) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE action IN (
             'client_create', 'client_update', 'client_secret_rotate',
             'client_delete', 'client_disabled', 'client_active'
         )",
    )
    .fetch_one(database)
    .await
    .expect("audit count")
}

async fn wait_for_actor_lock(database: &chenxing_auth::sqlx::PgPool, blocker_pid: i32) {
    timeout(Duration::from_secs(15), async {
        loop {
            let blocked: bool = chenxing_auth::sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                     FROM pg_stat_activity
                     WHERE $1 = ANY(pg_blocking_pids(pid))
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(database)
            .await
            .expect("inspect PostgreSQL lock wait");
            if blocked {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client write never reached the actor row lock");
}

fn assert_session_invalid<T: std::fmt::Debug>(label: &str, result: Result<T, ClientServiceError>) {
    match result {
        Err(ClientServiceError::ManagementActor(
            ManagementActorValidationError::SessionInvalid,
        )) => {}
        other => panic!("{label} must roll back without returning a secret: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_session_rolls_back_client_and_app_link_writes() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = seed_owner(&env.database, &format!("owner-{suffix}")).await;
    let client_id = format!("cx-revoked-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients (
             client_id, client_name, client_secret_hash, redirect_uris, scopes,
             auth_method, status, owner_user_id, created_at
         ) VALUES (
             $1, 'original', 'not-a-real-hash',
             '[\"https://app.example/callback\"]'::jsonb, '[\"openid\"]'::jsonb,
             'client_secret_basic', 'active', $2, NOW()
         )",
    )
    .bind(&client_id)
    .bind(actor_id)
    .execute(&env.database)
    .await
    .expect("seed client");

    let revoked = save_session(&env, actor_id).await;
    let live = save_session(&env, actor_id).await;
    let revoked_credential = credential(actor_id, &revoked);
    let live_credential = credential(actor_id, &live);
    let epoch_before: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&env.database)
            .await
            .expect("session epoch");
    assert_eq!(client_count(&env.database).await, 1);

    let mut actor_lock = env.database.begin().await.expect("begin actor lock");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *actor_lock)
        .await
        .expect("actor lock backend pid");
    chenxing_auth::sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(actor_id)
        .fetch_one(&mut *actor_lock)
        .await
        .expect("lock actor user row");

    let create_task = {
        let clients = env.state.clients.clone();
        tokio::spawn(async move {
            clients
                .register_with_audit(
                    Some(actor_id),
                    registration("should-not-land"),
                    revoked_credential,
                    move |client| {
                        audit(
                            actor_id,
                            AuditAction::ClientCreate,
                            Some(client.client_id.clone()),
                        )
                    },
                )
                .await
        })
    };
    let update_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .update_with_audit(
                    &client_id,
                    registration("renamed"),
                    revoked_credential,
                    audit(actor_id, AuditAction::ClientUpdate, Some(client_id.clone())),
                )
                .await
        })
    };
    let status_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .set_status_with_audit(
                    &client_id,
                    "disabled",
                    revoked_credential,
                    audit(
                        actor_id,
                        AuditAction::ClientDisabled,
                        Some(client_id.clone()),
                    ),
                )
                .await
        })
    };
    let delete_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .delete_with_audit(
                    &client_id,
                    revoked_credential,
                    audit(actor_id, AuditAction::ClientDelete, Some(client_id.clone())),
                )
                .await
        })
    };
    let rotate_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .rotate_secret_with_audit(
                    &client_id,
                    revoked_credential,
                    audit(
                        actor_id,
                        AuditAction::ClientSecretRotate,
                        Some(client_id.clone()),
                    ),
                )
                .await
        })
    };
    let upsert_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .upsert_app_link(
                    &client_id,
                    "com.example.app".to_owned(),
                    vec![FINGERPRINT.to_owned()],
                    revoked_credential,
                    audit(actor_id, AuditAction::ClientUpdate, Some(client_id.clone())),
                )
                .await
        })
    };
    let clear_link_task = {
        let clients = env.state.clients.clone();
        let client_id = client_id.clone();
        tokio::spawn(async move {
            clients
                .delete_app_link(
                    &client_id,
                    revoked_credential,
                    audit(actor_id, AuditAction::ClientUpdate, Some(client_id.clone())),
                )
                .await
        })
    };

    wait_for_actor_lock(&env.database, blocker_pid).await;
    env.state
        .sessions
        .revoke(&revoked.token)
        .await
        .expect("revoke authenticated session without advancing user epoch");
    actor_lock.commit().await.expect("release actor row lock");

    assert_session_invalid("create", create_task.await.expect("create task"));
    assert_session_invalid("update", update_task.await.expect("update task"));
    assert_session_invalid("status", status_task.await.expect("status task"));
    assert_session_invalid("delete", delete_task.await.expect("delete task"));
    assert_session_invalid("rotate", rotate_task.await.expect("rotate task"));
    assert_session_invalid("app link upsert", upsert_task.await.expect("upsert task"));
    assert_session_invalid(
        "app link delete",
        clear_link_task.await.expect("delete app link task"),
    );

    let idempotent_create = env
        .state
        .clients
        .register_with_audit_idempotent(
            Some(actor_id),
            registration("idempotent-should-not-land"),
            revoked_credential,
            format!("admin:user:{actor_id}"),
            IdempotencyKey::parse(&format!("revoked-create-{suffix}")).expect("create key"),
            move |client| {
                audit(
                    actor_id,
                    AuditAction::ClientCreate,
                    Some(client.client_id.clone()),
                )
            },
        )
        .await;
    assert_session_invalid("idempotent create", idempotent_create);
    let idempotent_rotate = env
        .state
        .clients
        .rotate_secret_with_audit_idempotent(
            &client_id,
            revoked_credential,
            format!("admin:user:{actor_id}"),
            IdempotencyKey::parse(&format!("revoked-rotate-{suffix}")).expect("rotate key"),
            audit(
                actor_id,
                AuditAction::ClientSecretRotate,
                Some(client_id.clone()),
            ),
        )
        .await;
    assert_session_invalid("idempotent rotate", idempotent_rotate);

    let after = snapshot(&env.database, &client_id).await;
    assert_eq!(after.name, "original");
    assert_eq!(after.version, 0);
    assert_eq!(after.status, "active");
    assert!(!after.has_link);
    assert_eq!(client_count(&env.database).await, 1);
    assert_eq!(security_audit_count(&env.database).await, 0);
    let epoch_after: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&env.database)
            .await
            .expect("session epoch after revoke");
    assert_eq!(epoch_after, epoch_before);

    let renamed = env
        .state
        .clients
        .update_with_audit(
            &client_id,
            registration("live-rename"),
            live_credential,
            audit(actor_id, AuditAction::ClientUpdate, Some(client_id.clone())),
        )
        .await
        .expect("live sibling session update");
    assert!(renamed);
    assert_eq!(
        snapshot(&env.database, &client_id).await.name,
        "live-rename"
    );
    assert_eq!(client_count(&env.database).await, 1);

    env.cleanup().await;
}
