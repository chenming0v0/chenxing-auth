use crate::sqlx::PgPool;
use crate::users::domain::UserId;

use super::AuditedClientMutationError;

pub async fn update_client_with_audit(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(name)
    .bind(serde_json::to_value(redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(scopes).expect("scopes are serializable"))
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn set_client_status_with_audit(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    status: &str,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET status = $3
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(status)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn update_client(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(name)
    .bind(serde_json::to_value(redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(scopes).expect("scopes are serializable"))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn set_client_status(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET status = $3
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
