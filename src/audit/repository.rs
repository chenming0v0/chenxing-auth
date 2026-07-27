use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::AuditEvent;

pub async fn insert(pool: &PgPool, event: &AuditEvent) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events
         (id, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(event.id)
    .bind(&event.actor_type)
    .bind(&event.actor_id)
    .bind(&event.action)
    .bind(&event.resource_type)
    .bind(&event.resource_id)
    .bind(serde_json::Value::Object(event.metadata.clone()))
    .bind(event.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list(pool: &PgPool, limit: i64) -> Result<Vec<AuditEvent>, sqlx::Error> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            serde_json::Value,
            OffsetDateTime,
        ),
    >(
        "SELECT id, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at
         FROM audit_events ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(
                    id,
                    actor_type,
                    actor_id,
                    action,
                    resource_type,
                    resource_id,
                    metadata,
                    created_at,
                )| AuditEvent {
                    id,
                    actor_type,
                    actor_id,
                    action,
                    resource_type,
                    resource_id,
                    metadata: metadata.as_object().cloned().unwrap_or_default(),
                    created_at,
                },
            )
            .collect()
    })
}
