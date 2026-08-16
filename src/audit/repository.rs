use crate::sqlx::PgPool;
use time::OffsetDateTime;

use super::{
    AuditError, AuditEvent, SecurityEvent, SecurityEventClient, SecurityEventDetail, classify,
    security_event_request_context,
};

type AuditRow = (
    i64,
    String,
    Option<i64>,
    String,
    String,
    Option<String>,
    serde_json::Value,
    OffsetDateTime,
);

type SecurityEventRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    OffsetDateTime,
);

type SecurityEventDetailRow = (
    i64,
    String,
    String,
    Option<String>,
    serde_json::Value,
    OffsetDateTime,
    Option<String>,
    Option<OffsetDateTime>,
    Option<String>,
);

/// 写入一个审计事件，执行器由调用方给出。
///
/// 收成泛型 executor 而不是固定 `&PgPool`，是为了让「业务写入与它的审计记录必须
/// 同生共死」的路径（Owner 引导与管理侧安全设置，Issue #304、#502）能把这条
/// INSERT 放进业务事务里：
/// 事务回滚时审计行随之消失，事务提交时审计行必然已经落库，不存在
/// 「业务已提交、审计事后 best-effort 丢失」的中间态。
///
/// 事务内调用时不要在外层加重试：语句失败会让整个事务进入 aborted 状态，
/// 重试只会连续拿到 25P02。重试策略属于 [`super::AuditService::record`] 那条
/// 独立连接的路径。
pub(crate) async fn insert_with<'executor, E>(
    executor: E,
    event: &AuditEvent,
) -> Result<(), AuditError>
where
    E: crate::sqlx::Executor<'executor, Database = crate::sqlx::Postgres>,
{
    let mut event = event.clone();
    event.redact_metadata_in_place();
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
    .execute(executor)
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
    list_filtered_with(pool, action, resource_type, limit, offset).await
}

pub async fn query_filtered(
    pool: &PgPool,
    action: Option<&str>,
    resource_type: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<AuditEvent>, i64), crate::sqlx::Error> {
    // COUNT and page rows must observe one MVCC snapshot.
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let total = count_filtered_with(&mut *transaction, action, resource_type).await?;
    let events =
        list_filtered_with(&mut *transaction, action, resource_type, limit, offset).await?;
    transaction.commit().await?;
    Ok((events, total))
}

/// 查询单个用户可见的安全事件，热表和归档表必须处于同一 MVCC 快照。
pub async fn query_security_events(
    pool: &PgPool,
    actor_user_id: i64,
    limit: i64,
    offset: i64,
) -> Result<(Vec<SecurityEvent>, i64), crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let total: i64 = crate::sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1) +
             (SELECT COUNT(*) FROM audit_events_archive WHERE actor_user_id = $1)",
    )
    .bind(actor_user_id)
    .fetch_one(&mut *transaction)
    .await?;
    let rows = crate::sqlx::query_as::<_, SecurityEventRow>(
        "WITH event_rows AS (
             SELECT id, action, resource_type, resource_id, created_at
             FROM audit_events
             WHERE actor_user_id = $1
             UNION ALL
             SELECT id, action, resource_type, resource_id, created_at
             FROM audit_events_archive
             WHERE actor_user_id = $1
         ), safe_events AS (
             SELECT id, action, resource_type,
                    CASE WHEN resource_type IN
                         ('oauth_authorization', 'oauth_client', 'oauth_consent', 'oauth_token')
                         THEN resource_id
                         ELSE NULL
                    END AS client_id,
                    created_at
             FROM event_rows
         )
         SELECT event.id, event.action, event.resource_type, event.client_id,
                client.client_name, event.created_at
         FROM safe_events AS event
         LEFT JOIN oauth_clients AS client ON client.client_id = event.client_id
         ORDER BY event.created_at DESC, event.id DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(actor_user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let events = rows
        .into_iter()
        .map(
            |(id, action, resource_type, client_id, client_name, created_at)| {
                let (category, severity) = classify(&action);
                SecurityEvent {
                    id,
                    action,
                    category,
                    severity,
                    resource_type,
                    client_id,
                    client_name,
                    created_at,
                }
            },
        )
        .collect();
    Ok((events, total))
}

/// 查询单个用户可见的安全事件详情（Issue #308）。
///
/// 归属（`actor_user_id = $1`）与事件 id 在同一查询内判定：查不到和「不是你的」
/// 都返回 `None`，由调用方统一映射成 404，不做可枚举的区分。热表和归档表处于
/// 同一 MVCC 快照；Client 信息只在资源类型命中白名单时从 `oauth_clients` 表提取，
/// Client 已删除时各列自然为 NULL，映射为 `client: None`。
pub async fn query_security_event(
    pool: &PgPool,
    actor_user_id: i64,
    event_id: i64,
) -> Result<Option<SecurityEventDetail>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, SecurityEventDetailRow>(
        "WITH event_rows AS (
             SELECT id, action, resource_type, resource_id, metadata, created_at
             FROM audit_events
             WHERE actor_user_id = $1 AND id = $2
             UNION ALL
             SELECT id, action, resource_type, resource_id, metadata, created_at
             FROM audit_events_archive
             WHERE actor_user_id = $1 AND id = $2
         ), safe_events AS (
             SELECT id, action, resource_type,
                    CASE WHEN resource_type IN
                         ('oauth_authorization', 'oauth_client', 'oauth_consent', 'oauth_token')
                         THEN resource_id
                         ELSE NULL
                    END AS client_id,
                    metadata, created_at
             FROM event_rows
         )
         SELECT event.id, event.action, event.resource_type, event.client_id,
                event.metadata, event.created_at,
                client.client_name, client.created_at, client.status
         FROM safe_events AS event
         LEFT JOIN oauth_clients AS client ON client.client_id = event.client_id
         ORDER BY event.created_at DESC, event.id DESC
         LIMIT 1",
    )
    .bind(actor_user_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    let Some((
        id,
        action,
        resource_type,
        client_id,
        metadata,
        created_at,
        client_name,
        client_created_at,
        client_status,
    )) = row
    else {
        return Ok(None);
    };
    let (category, severity) = classify(&action);
    let (ip, user_agent) = match metadata {
        serde_json::Value::Object(metadata) => security_event_request_context(&metadata),
        // metadata 非对象时防御性回落：详情接口不因脏数据 500。
        _ => (None, None),
    };
    let client = match (client_id, client_name, client_created_at, client_status) {
        (Some(client_id), Some(client_name), Some(created_at), Some(status)) => {
            Some(SecurityEventClient {
                client_id,
                client_name,
                created_at,
                status,
            })
        }
        _ => None,
    };
    Ok(Some(SecurityEventDetail {
        id,
        action,
        category,
        severity,
        resource_type,
        created_at,
        ip,
        ip_location: None,
        user_agent,
        ray_id: None,
        client,
    }))
}

async fn list_filtered_with<'executor, E>(
    executor: E,
    action: Option<&str>,
    resource_type: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditEvent>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'executor, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query_as::<_, AuditRow>(
        "WITH event_rows AS (
             SELECT id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at
             FROM audit_events
             UNION ALL
             SELECT id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at
             FROM audit_events_archive
         )
         SELECT id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at
         FROM event_rows
         WHERE ($1::text IS NULL OR action = $1)
           AND ($2::text IS NULL OR resource_type = $2)
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(action)
    .bind(resource_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(executor)
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
    count_filtered_with(pool, action, resource_type).await
}

async fn count_filtered_with<'executor, E>(
    executor: E,
    action: Option<&str>,
    resource_type: Option<&str>,
) -> Result<i64, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'executor, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query_scalar(
        "WITH event_rows AS (
             SELECT action, resource_type FROM audit_events
             UNION ALL
             SELECT action, resource_type FROM audit_events_archive
         )
         SELECT COUNT(*) FROM event_rows
         WHERE ($1::text IS NULL OR action = $1)
           AND ($2::text IS NULL OR resource_type = $2)",
    )
    .bind(action)
    .bind(resource_type)
    .fetch_one(executor)
    .await
}

pub async fn archive_expired(
    pool: &PgPool,
    retention_days: i32,
) -> Result<i64, crate::sqlx::Error> {
    let archived: i32 = crate::sqlx::query_scalar("SELECT archive_audit_events($1, $2)")
        .bind(retention_days)
        .bind(super::AUDIT_ARCHIVE_BATCH_SIZE)
        .fetch_one(pool)
        .await?;
    Ok(i64::from(archived))
}
