use crate::clients::domain::ValidatedClientRegistration;
use crate::sqlx::PgPool;
use crate::users::ManagementActorCredential;
use crate::users::domain::{UserId, UserPermission};

use super::AuditedClientMutationError;

pub async fn update_client_with_audit(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    registration: &ValidatedClientRegistration,
    management_actor: ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        Some(management_actor),
        UserPermission::ManageClients,
    )
    .await?;
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5, logo_uri = $6, client_uri = $7, description = $8
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(&registration.client_name)
    .bind(serde_json::to_value(&registration.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&registration.scopes).expect("scopes are serializable"))
    .bind(&registration.logo_uri)
    .bind(&registration.client_uri)
    .bind(&registration.description)
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
    management_actor: ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        Some(management_actor),
        UserPermission::ManageClients,
    )
    .await?;
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

pub async fn delete_client_with_audit(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    management_actor: Option<ManagementActorCredential>,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        management_actor,
        UserPermission::ManageClients,
    )
    .await?;
    let result = crate::sqlx::query(
        "DELETE FROM oauth_clients
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
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
    registration: &ValidatedClientRegistration,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5, logo_uri = $6, client_uri = $7, description = $8
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(&registration.client_name)
    .bind(serde_json::to_value(&registration.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&registration.scopes).expect("scopes are serializable"))
    .bind(&registration.logo_uri)
    .bind(&registration.client_uri)
    .bind(&registration.description)
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
