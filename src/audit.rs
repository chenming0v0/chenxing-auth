use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod repository;

#[derive(Clone)]
pub struct AuditService {
    pool: crate::sqlx::PgPool,
}

impl AuditService {
    pub fn new(pool: crate::sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, event: AuditEvent) {
        if let Err(error) = repository::insert(&self.pool, &event).await {
            tracing::error!(error = %error, action = %event.action, "failed to persist audit event");
        }
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<AuditEvent>, crate::sqlx::Error> {
        repository::list(&self.pool, limit.clamp(1, 200)).await
    }

    pub async fn query(
        &self,
        action: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AuditEvent>, i64), crate::sqlx::Error> {
        let total = repository::count_filtered(&self.pool, action, resource_type).await?;
        let events = repository::list_filtered(
            &self.pool,
            action,
            resource_type,
            limit.clamp(1, 100),
            offset.max(0),
        )
        .await?;
        Ok((events, total))
    }

    pub async fn count(&self) -> Result<i64, crate::sqlx::Error> {
        repository::count_filtered(&self.pool, None, None).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub metadata: Map<String, Value>,
    pub created_at: OffsetDateTime,
}

impl AuditEvent {
    pub fn new(
        actor_type: String,
        actor_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        metadata: Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            metadata: redact_metadata(metadata),
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

fn redact_metadata(metadata: Value) -> Map<String, Value> {
    let Value::Object(mut metadata) = metadata else {
        return Map::new();
    };
    for key in [
        "password",
        "password_hash",
        "client_secret",
        "client_secret_hash",
        "access_token",
        "refresh_token",
        "authorization_code",
    ] {
        metadata.remove(key);
    }
    metadata
}
