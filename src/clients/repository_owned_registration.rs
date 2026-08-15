//! User-owned OAuth Client creation and quota enforcement.

use time::OffsetDateTime;

use super::{
    AuditedClientInsertError, ClientCredential, ClientInsertError, NewClient, insert_client_row,
};
use crate::{clients::domain::ValidatedClientRegistration, sqlx::PgPool, users::domain::UserId};

pub(super) async fn effective_limit(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    owner_user_id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    let (plan_id, plan_expires_at): (Option<i64>, Option<OffsetDateTime>) = crate::sqlx::query_as(
        "SELECT plan_id, plan_expires_at FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(owner_user_id)
    .fetch_one(&mut **transaction)
    .await?;
    let user_plan: Option<(i32, String, bool)> = if let Some(plan_id) = plan_id {
        crate::sqlx::query_as(
            "SELECT oauth_clients_limit, status,
                    ($2::timestamptz IS NULL OR $2 > NOW()) AS assignment_active
             FROM plans WHERE id = $1 FOR UPDATE",
        )
        .bind(plan_id)
        .bind(plan_expires_at)
        .fetch_optional(&mut **transaction)
        .await?
    } else {
        None
    };
    let default_plan: Option<(i32,)> = crate::sqlx::query_as(
        "SELECT oauth_clients_limit FROM plans
         WHERE is_default = TRUE AND status = 'active'
         FOR UPDATE",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(user_plan
        .filter(|(_, status, assignment_active)| status == "active" && *assignment_active)
        .map(|(limit, _, _)| i64::from(limit))
        .or_else(|| default_plan.map(|(limit,)| i64::from(limit))))
}

pub(super) async fn quota_available(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
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

pub async fn insert_owned_client(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
) -> Result<NewClient, ClientInsertError> {
    let mut transaction = pool.begin().await?;
    let Some(limit) = effective_limit(&mut transaction, owner_user_id).await? else {
        transaction.rollback().await?;
        return Err(ClientInsertError::QuotaExceeded);
    };
    if !quota_available(&mut transaction, owner_user_id, limit).await? {
        transaction.rollback().await?;
        return Err(ClientInsertError::QuotaExceeded);
    }
    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        &mut *transaction,
        &registration,
        &client_id,
        &credential,
        created_at,
        Some(owner_user_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(NewClient {
        id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id: Some(owner_user_id),
        auth_method: credential.auth_method(),
    })
}

pub async fn insert_owned_client_with_audit<F>(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    audit_event: F,
) -> Result<NewClient, AuditedClientInsertError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let mut transaction = pool.begin().await?;
    let Some(limit) = effective_limit(&mut transaction, owner_user_id).await? else {
        transaction.rollback().await?;
        return Err(AuditedClientInsertError::QuotaExceeded);
    };
    if !quota_available(&mut transaction, owner_user_id, limit).await? {
        transaction.rollback().await?;
        return Err(AuditedClientInsertError::QuotaExceeded);
    }
    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        &mut *transaction,
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
    crate::audit::repository::insert_with(&mut *transaction, &audit_event(&client))
        .await
        .map_err(AuditedClientInsertError::Audit)?;
    transaction.commit().await?;
    Ok(client)
}
