use chenxing_auth::{
    audit::{AuditAction, AuditEvent},
    clients::{domain::ClientAuthMethod, service::ClientRegistrationRequest},
    plans::domain::AuthQuotaLimits,
};
use uuid::Uuid;

pub(super) const DEFAULT_DAILY_LIMIT: u64 = 11;
pub(super) const PAID_DAILY_LIMIT: u64 = 900;

pub(super) struct Fixture {
    pub env: crate::harness::Harness,
    pub user_id: i64,
    pub plan_id: i64,
}

impl Fixture {
    pub async fn new(default_limit: Option<i32>, has_client: bool) -> Self {
        let env = crate::harness::HarnessBuilder::new("client_plan_expiry")
            .max_connections(16)
            .build()
            .await;
        crate::plan_fixtures::clear_all_plans(&env.database).await;
        if let Some(limit) = default_limit {
            let id = crate::plan_fixtures::seed_default_plan(&env.database).await;
            chenxing_auth::sqlx::query(
                "UPDATE plans SET oauth_clients_limit = $2, daily_auth_limit = $3,
                                  monthly_auth_limit = NULL WHERE id = $1",
            )
            .bind(id)
            .bind(limit)
            .bind(DEFAULT_DAILY_LIMIT as i64)
            .execute(&env.database)
            .await
            .expect("configure default quota");
        }
        let suffix = Uuid::new_v4().simple().to_string();
        let user_id = chenxing_auth::sqlx::query_scalar(
            "INSERT INTO users (username, email, canonical_email, password_hash)
             VALUES ($1, $2, lower($2), 'not-a-real-hash') RETURNING id",
        )
        .bind(format!("quota-{suffix}"))
        .bind(format!("quota-{suffix}@example.com"))
        .fetch_one(&env.database)
        .await
        .expect("seed quota owner");
        let plan_id = crate::plan_fixtures::assign_private_plan(
            &env.database,
            user_id,
            crate::plan_fixtures::PlanLimits {
                oauth_clients_limit: 10,
                daily_auth_limit: PAID_DAILY_LIMIT as i64,
                monthly_auth_limit: Some(9_000),
                max_qps: None,
            },
        )
        .await;
        if has_client {
            chenxing_auth::sqlx::query(
                "INSERT INTO oauth_clients (
                     client_id, client_name, redirect_uris, scopes, auth_method,
                     status, owner_user_id, quota_exempt, created_at
                 ) VALUES ($1, 'existing', '[\"https://app.example/callback\"]'::jsonb,
                           '[\"openid\"]'::jsonb, 'none', 'active', $2, false, NOW())",
            )
            .bind(format!("cx-existing-{suffix}"))
            .bind(user_id)
            .execute(&env.database)
            .await
            .expect("seed counted client");
        }
        Self {
            env,
            user_id,
            plan_id,
        }
    }

    pub async fn assert_effects(&self, clients: i64, audits: i64) {
        let count: i64 = chenxing_auth::sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_clients WHERE owner_user_id = $1",
        )
        .bind(self.user_id)
        .fetch_one(&self.env.database)
        .await
        .expect("count owned clients");
        assert_eq!(count, clients);
        let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'client_create'",
        )
        .fetch_one(&self.env.database)
        .await
        .expect("count client creation audit");
        assert_eq!(audit_count, audits);
    }
}

pub(super) fn registration(name: &str) -> ClientRegistrationRequest {
    ClientRegistrationRequest {
        registration: chenxing_auth::clients::domain::ClientRegistrationInput {
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

pub(super) fn audit(
    user_id: i64,
    client: &chenxing_auth::clients::repository::NewClient,
) -> AuditEvent {
    AuditEvent::new(
        "user".to_owned(),
        Some(user_id.to_string()),
        AuditAction::ClientCreate,
        "oauth_client".to_owned(),
        Some(client.client_id.clone()),
        serde_json::json!({"result": "success"}),
    )
}

pub(super) fn default_auth_limits() -> AuthQuotaLimits {
    AuthQuotaLimits {
        daily_auth_limit: DEFAULT_DAILY_LIMIT,
        monthly_auth_limit: None,
    }
}
