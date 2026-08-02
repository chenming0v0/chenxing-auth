use crate::sqlx::PgPool;
use time::OffsetDateTime;

use super::{AuditError, AuditEvent};

pub async fn insert(pool: &PgPool, event: &AuditEvent) -> Result<(), AuditError> {
    event.validate()?;
    let actor_user_id = event
        .actor_id
        .as_deref()
        .map(|id| id.parse::<i64>().map_err(|_| AuditError::InvalidActorId))
        .transpose()?;
    crate::sqlx::query(
        "INSERT INTO audit_events
         (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&event.actor_type)
    .bind(actor_user_id)
    .bind(&event.action)
    .bind(&event.resource_type)
    .bind(&event.resource_id)
    .bind(serde_json::Value::Object(event.metadata.clone()))
    .bind(event.created_at)
    .execute(pool)
    .await
    .map_err(AuditError::Database)?;
    Ok(())
}

pub async fn list(pool: &PgPool, limit: i64) -> Result<Vec<AuditEvent>, crate::sqlx::Error> {
    list_filtered(pool, None, None, limit, 0).await
}

pub async fn list_filtered(
    pool: &PgPool,
    action: Option<&str>,
    resource_type: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditEvent>, crate::sqlx::Error> {
    crate::sqlx::query_as::<
        _,
        (
            i64,
            String,
            Option<i64>,
            String,
            String,
            Option<String>,
            serde_json::Value,
            OffsetDateTime,
        ),
    >(
        "SELECT id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at
         FROM audit_events
         WHERE ($1::text IS NULL OR action = $1)
           AND ($2::text IS NULL OR resource_type = $2)
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(action)
    .bind(resource_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(
                    id,
                    actor_type,
                    actor_user_id,
                    action,
                    resource_type,
                    resource_id,
                    metadata,
                    created_at,
                )| AuditEvent {
                    id,
                    actor_type,
                    actor_id: actor_user_id.map(|id| id.to_string()),
                    action,
                    resource_type,
                    resource_id,
                    metadata: super::redact_metadata(metadata),
                    created_at,
                },
            )
            .collect()
    })
}

pub async fn count_filtered(
    pool: &PgPool,
    action: Option<&str>,
    resource_type: Option<&str>,
) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE ($1::text IS NULL OR action = $1)
           AND ($2::text IS NULL OR resource_type = $2)",
    )
    .bind(action)
    .bind(resource_type)
    .fetch_one(pool)
    .await
}
