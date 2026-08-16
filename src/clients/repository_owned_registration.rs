//! User-owned OAuth Client creation and quota enforcement.
//!
//! 配额解析必须与套餐仓储共享同一把锁序（用户行 → DefaultPlan 业务锁 → 套餐行），
//! 且只在调用方事务内解析；事务外的套餐快照会让降级/归档/到期回退出现越界窗口
//! （Issue #479）。「没有生效套餐」返回 `None`，由上层表达为自助通道关闭，
//! 不与「配额用尽」混同。

use time::OffsetDateTime;

use super::{
    AuditedClientInsertError, ClientCredential, ClientInsertError, NewClient, NewOwnedClient,
    insert_client_row,
};
use crate::{clients::domain::ValidatedClientRegistration, sqlx::PgPool, users::domain::UserId};

type Transaction<'a> = crate::sqlx::Transaction<'a, crate::sqlx::Postgres>;

pub(super) async fn effective_limit(
    transaction: &mut Transaction<'_>,
    owner_user_id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    Ok(
        crate::plans::repository::lock_effective_for_user(transaction, owner_user_id)
            .await?
            .map(|plan| i64::from(plan.oauth_clients_limit)),
    )
}

pub(super) async fn quota_available(
    transaction: &mut Transaction<'_>,
    owner_user_id: UserId,
    limit: i64,
) -> Result<bool, crate::sqlx::Error> {
    let count: i64 =
        crate::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients WHERE owner_user_id = $1")
            .bind(owner_user_id)
            .fetch_one(&mut **transaction)
            .await?;
    Ok(count < limit)
}

async fn locked_effective_plan(
    transaction: &mut Transaction<'_>,
    owner_user_id: UserId,
) -> Result<Option<crate::plans::domain::Plan>, crate::sqlx::Error> {
    crate::plans::repository::lock_effective_for_user(transaction, owner_user_id).await
}

pub async fn insert_owned_client(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
) -> Result<Option<NewOwnedClient>, ClientInsertError> {
    let mut transaction = pool.begin().await?;
    let owned = match insert_owned_client_in_transaction(
        &mut transaction,
        owner_user_id,
        registration,
        client_id,
        credential,
        None::<fn(&NewClient) -> crate::audit::AuditEvent>,
    )
    .await
    {
        Ok(owned) => owned,
        Err(error) => {
            transaction.rollback().await?;
            return Err(error.into());
        }
    };
    transaction.commit().await?;
    Ok(owned)
}

pub async fn insert_owned_client_with_audit<F>(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    audit_event: F,
) -> Result<Option<NewOwnedClient>, AuditedClientInsertError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let mut transaction = pool.begin().await?;
    let owned = match insert_owned_client_in_transaction(
        &mut transaction,
        owner_user_id,
        registration,
        client_id,
        credential,
        Some(audit_event),
    )
    .await
    {
        Ok(owned) => owned,
        Err(error) => {
            transaction.rollback().await?;
            return Err(error.into());
        }
    };
    transaction.commit().await?;
    Ok(owned)
}

/// 在调用方事务内完成「锁定套餐 → 配额检查 → 插入 →（可选）审计」。
/// `Ok(None)` 表示没有生效套餐；审计与 Client 插入同事务提交，二者要么都
/// 落地要么都不生效（Issue #502 的审计边界）。
async fn insert_owned_client_in_transaction<F>(
    transaction: &mut Transaction<'_>,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    audit_event: Option<F>,
) -> Result<Option<NewOwnedClient>, InsertError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let Some(effective_plan) = locked_effective_plan(transaction, owner_user_id).await? else {
        return Ok(None);
    };
    let limit = i64::from(effective_plan.oauth_clients_limit);
    if !quota_available(transaction, owner_user_id, limit).await? {
        return Err(InsertError::QuotaExceeded);
    }
    // 保留墙钟（Issue #299 的明确例外）：行创建时间。
    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        &mut **transaction,
        &registration,
        &client_id,
        &credential,
        created_at,
        Some(owner_user_id),
    )
    .await?;
    let client = NewClient {
        id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id: Some(owner_user_id),
        auth_method: credential.auth_method(),
    };
    if let Some(audit_event) = audit_event {
        crate::audit::repository::insert_with(&mut **transaction, &audit_event(&client))
            .await
            .map_err(InsertError::Audit)?;
    }
    Ok(Some(NewOwnedClient {
        client,
        quota_limits: effective_plan.auth_quota_limits(),
    }))
}

#[derive(Debug)]
enum InsertError {
    QuotaExceeded,
    Database(crate::sqlx::Error),
    Audit(crate::audit::AuditError),
}

impl From<crate::sqlx::Error> for InsertError {
    fn from(error: crate::sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<InsertError> for ClientInsertError {
    fn from(error: InsertError) -> Self {
        match error {
            InsertError::QuotaExceeded => ClientInsertError::QuotaExceeded,
            InsertError::Database(error) => ClientInsertError::Database(error),
            // 非审计包装层不传入审计回调；该分支在类型上可达、在运行时不可达。
            InsertError::Audit(error) => ClientInsertError::Database(crate::sqlx::Error::Protocol(
                format!("owned client audit failed: {error}"),
            )),
        }
    }
}

impl From<InsertError> for AuditedClientInsertError {
    fn from(error: InsertError) -> Self {
        match error {
            InsertError::QuotaExceeded => AuditedClientInsertError::QuotaExceeded,
            InsertError::Database(error) => AuditedClientInsertError::Database(error),
            InsertError::Audit(error) => AuditedClientInsertError::Audit(error),
        }
    }
}
