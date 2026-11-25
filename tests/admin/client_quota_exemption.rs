//! #748：管理创建始终免套餐额度，幂等重放不重复占额或记录审计。

use chenxing_auth::{
    audit::{AuditAction, AuditEvent},
    clients::{
        domain::{ClientAuthMethod, ClientRegistrationInput},
        idempotency::IdempotencyKey,
        service::{ClientRegistrationRequest, ClientServiceError},
    },
    users::ManagementActorCredential,
};
use uuid::Uuid;

fn registration(name: &str) -> ClientRegistrationRequest {
    ClientRegistrationRequest {
        registration: ClientRegistrationInput {
            client_name: name.to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            logo_uri: None,
            client_uri: None,
            description: None,
        },
        auth_method: ClientAuthMethod::None,
    }
}

fn audit(client: &chenxing_auth::clients::repository::NewClient) -> AuditEvent {
    AuditEvent::new(
        "admin_token".to_owned(),
        None,
        AuditAction::ClientCreate,
        "oauth_client".to_owned(),
        Some(client.client_id.clone()),
        serde_json::json!({"result": "success"}),
    )
}

#[tokio::test]
async fn owned_admin_clients_and_replays_stay_exempt_from_self_service_quota() {
    let env = crate::harness::HarnessBuilder::new("admin_client_quota_exemption")
        .max_connections(8)
        .build()
        .await;
    crate::plan_fixtures::clear_all_plans(&env.database).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash)
         VALUES ($1, $2, lower($2), 'not-a-real-hash') RETURNING id",
    )
    .bind(format!("exempt-{suffix}"))
    .bind(format!("exempt-{suffix}@example.com"))
    .fetch_one(&env.database)
    .await
    .expect("seed stamped owner");

    let closed = env
        .state
        .clients
        .register_for_user(user_id, registration("closed"))
        .await
        .expect("self-service availability");
    assert!(closed.is_none());
    env.state
        .clients
        .register_with_audit(
            Some(user_id),
            registration("admin"),
            ManagementActorCredential::SystemToken,
            audit,
        )
        .await
        .expect("admin creation does not require a plan");
    let idempotent = env
        .state
        .clients
        .register_with_audit_idempotent(
            Some(user_id),
            registration("idempotent-admin"),
            ManagementActorCredential::SystemToken,
            "admin_token".to_owned(),
            IdempotencyKey::parse("exempt-admin").expect("key"),
            audit,
        )
        .await
        .expect("idempotent admin creation does not require a plan");
    let replay = env
        .state
        .clients
        .register_with_audit_idempotent(
            Some(user_id),
            registration("idempotent-admin"),
            ManagementActorCredential::SystemToken,
            "admin_token".to_owned(),
            IdempotencyKey::parse("exempt-admin").expect("key"),
            audit,
        )
        .await
        .expect("replay while self-service is closed");
    assert_eq!(replay.client_id, idempotent.client_id);

    let plan_id = crate::plan_fixtures::seed_default_plan(&env.database).await;
    chenxing_auth::sqlx::query("UPDATE plans SET oauth_clients_limit = 1 WHERE id = $1")
        .bind(plan_id)
        .execute(&env.database)
        .await
        .expect("set self-service limit");
    env.state
        .clients
        .register_for_user_with_audit(user_id, registration("counted"), audit)
        .await
        .expect("exempt rows do not consume default quota")
        .expect("default plan");
    let full = env
        .state
        .clients
        .register_for_user(user_id, registration("over-limit"))
        .await;
    assert!(
        matches!(&full, Err(ClientServiceError::QuotaExceeded)),
        "{full:?}"
    );

    let (exempt, counted): (i64, i64) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE quota_exempt), COUNT(*) FILTER (WHERE NOT quota_exempt)
         FROM oauth_clients WHERE owner_user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&env.database)
    .await
    .expect("quota channels");
    assert_eq!((exempt, counted), (2, 1));
    let audits: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'client_create'",
    )
    .fetch_one(&env.database)
    .await
    .expect("creation audit count");
    assert_eq!(audits, 3);
    env.cleanup().await;
}
