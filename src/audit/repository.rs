use sqlx::PgPool;

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
