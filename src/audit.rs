use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod repository;

#[derive(Clone)]
pub struct AuditService {
    pool: sqlx::PgPool,
}

impl AuditService {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, event: AuditEvent) {
        if let Err(error) = repository::insert(&self.pool, &event).await {
            tracing::error!(error = %error, action = %event.action, "failed to persist audit event");
        }
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
