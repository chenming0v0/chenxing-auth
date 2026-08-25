//! Transactional persistence for one-time Client credential recovery.

use serde_json::Value;
use time::OffsetDateTime;

use super::{ClientCredential, NewClient, insert_client_row, owned_registration};
use crate::{
    clients::{
        domain::ValidatedClientRegistration,
        idempotency::{
            ClientIdempotencyContext, PersistedClientCreateResult, PersistedClientRotationResult,
        },
    },
    sqlx::{PgPool, types::Json},
    users::domain::UserId,
};

const IDEMPOTENCY_TTL_SECONDS: i32 = 24 * 60 * 60;

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdempotentClientOperationError {
    #[error("normal user OAuth project quota has been exhausted")]
    QuotaExceeded,
    #[error("client mutation lost a concurrent compare-and-swap")]
    MutationConflict,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("stored idempotency result is invalid")]
    CorruptResult,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

#[derive(Debug)]
pub(crate) struct IdempotentPersisted<T> {
    pub value: T,
    pub secret_kid: String,
    /// Whether this request applied the mutation instead of replaying a
    /// previously committed idempotency result.
    pub applied: bool,
}

enum Claim {
    New { secret_kid: String },
    Replay { secret_kid: String, result: Value },
}

pub(crate) struct IdempotentClientInsert<'a, F> {
    pub owner_user_id: Option<UserId>,
    pub registration: ValidatedClientRegistration,
    pub client_id: String,
    pub credential: ClientCredential,
    pub context: &'a ClientIdempotencyContext,
    pub active_secret_kid: &'a str,
    pub audit_event: F,
}

pub(crate) async fn insert_client_idempotent_with_audit<F>(
    pool: &PgPool,
    request: IdempotentClientInsert<'_, F>,
) -> Result<IdempotentPersisted<PersistedClientCreateResult>, IdempotentClientOperationError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let IdempotentClientInsert {
        owner_user_id,
        registration,
        client_id,
        credential,
        context,
        active_secret_kid,
        audit_event,
    } = request;
    let mut transaction = pool.begin().await?;
    match claim_operation(&mut transaction, context, active_secret_kid).await? {
        Claim::Replay { secret_kid, result } => {
            let value = serde_json::from_value(result)
                .map_err(|_| IdempotentClientOperationError::CorruptResult)?;
            transaction.rollback().await?;
            Ok(IdempotentPersisted {
                value,
                secret_kid,
                applied: false,
            })
        }
        Claim::New { secret_kid } => {
            if let Some(owner_user_id) = owner_user_id {
                let Some(limit) =
                    owned_registration::effective_limit(&mut transaction, owner_user_id).await?
                else {
                    transaction.rollback().await?;
                    return Err(IdempotentClientOperationError::QuotaExceeded);
                };
                if !owned_registration::quota_available(&mut transaction, owner_user_id, limit)
                    .await?
                {
                    transaction.rollback().await?;
                    return Err(IdempotentClientOperationError::QuotaExceeded);
                }
            }

            let created_at = OffsetDateTime::now_utc();
            let id = insert_client_row(
                &mut *transaction,
                &registration,
                &client_id,
                &credential,
                created_at,
                owner_user_id,
            )
            .await?;
            let client = NewClient {
                id,
                client_id,
                client_name: registration.client_name,
                redirect_uris: registration.redirect_uris,
                scopes: registration.scopes,
                created_at,
                owner_user_id,
                auth_method: credential.auth_method(),
                logo_uri: registration.logo_uri,
                client_uri: registration.client_uri,
                description: registration.description,
            };
            crate::audit::repository::insert_with(&mut *transaction, &audit_event(&client)).await?;
            let value = PersistedClientCreateResult {
                id: client.id,
                client_id: client.client_id,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                scopes: client.scopes,
                auth_method: client.auth_method.as_str().to_owned(),
                logo_uri: client.logo_uri,
                client_uri: client.client_uri,
                description: client.description,
            };
            complete_operation(&mut transaction, context, &value).await?;
            transaction.commit().await?;
            Ok(IdempotentPersisted {
                value,
                secret_kid,
                applied: true,
            })
        }
    }
}

pub(crate) struct IdempotentClientRotation<'a> {
    pub owner_user_id: Option<UserId>,
    pub client_id: &'a str,
    pub expected_version: i64,
    pub client_secret_hash: &'a str,
    pub context: &'a ClientIdempotencyContext,
    pub active_secret_kid: &'a str,
    pub audit_event: crate::audit::AuditEvent,
}

pub(crate) async fn rotate_client_secret_idempotent_with_audit(
    pool: &PgPool,
    request: IdempotentClientRotation<'_>,
) -> Result<IdempotentPersisted<PersistedClientRotationResult>, IdempotentClientOperationError> {
    let IdempotentClientRotation {
        owner_user_id,
        client_id,
        expected_version,
        client_secret_hash,
        context,
        active_secret_kid,
        audit_event,
    } = request;
    let mut transaction = pool.begin().await?;
    match claim_operation(&mut transaction, context, active_secret_kid).await? {
        Claim::Replay { secret_kid, result } => {
            let value = serde_json::from_value(result)
                .map_err(|_| IdempotentClientOperationError::CorruptResult)?;
            transaction.rollback().await?;
            Ok(IdempotentPersisted {
                value,
                secret_kid,
                applied: false,
            })
        }
        Claim::New { secret_kid } => {
            let result = crate::sqlx::query(
                "UPDATE oauth_clients
                 SET client_secret_hash = $3,
                     client_secret_version = client_secret_version + 1,
                     allow_legacy_refresh_tokens = FALSE
                 WHERE client_id = $1
                   AND ($2::bigint IS NULL OR owner_user_id = $2)
                   AND auth_method <> 'none'
                   AND status = 'active'
                   AND client_secret_version = $4",
            )
            .bind(client_id)
            .bind(owner_user_id)
            .bind(client_secret_hash)
            .bind(expected_version)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                transaction.rollback().await?;
                return Err(IdempotentClientOperationError::MutationConflict);
            }
            crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
            let value = PersistedClientRotationResult {
                client_id: client_id.to_owned(),
                secret_version: expected_version + 1,
            };
            complete_operation(&mut transaction, context, &value).await?;
            transaction.commit().await?;
            Ok(IdempotentPersisted {
                value,
                secret_kid,
                applied: true,
            })
        }
    }
}

async fn claim_operation(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    context: &ClientIdempotencyContext,
    active_secret_kid: &str,
) -> Result<Claim, IdempotentClientOperationError> {
    crate::sqlx::query(
        "DELETE FROM client_operation_idempotency
         WHERE actor_scope = $1 AND expires_at <= NOW()",
    )
    .bind(context.actor_scope())
    .execute(&mut **transaction)
    .await?;

    let key_digest = context.key_digest();
    let inserted = crate::sqlx::query(
        "INSERT INTO client_operation_idempotency
         (actor_scope, key_digest, operation, request_hash, secret_kid, expires_at)
         VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(secs => $6))
         ON CONFLICT (actor_scope, key_digest) DO NOTHING",
    )
    .bind(context.actor_scope())
    .bind(key_digest.as_slice())
    .bind(context.operation())
    .bind(context.request_hash().as_slice())
    .bind(active_secret_kid)
    .bind(IDEMPOTENCY_TTL_SECONDS)
    .execute(&mut **transaction)
    .await?
    .rows_affected()
        == 1;

    let (operation, request_hash, secret_kid, result_data): (
        String,
        Vec<u8>,
        String,
        Option<Json<Value>>,
    ) = crate::sqlx::query_as(
        "SELECT operation, request_hash, secret_kid, result_data
         FROM client_operation_idempotency
         WHERE actor_scope = $1 AND key_digest = $2
         FOR UPDATE",
    )
    .bind(context.actor_scope())
    .bind(key_digest.as_slice())
    .fetch_one(&mut **transaction)
    .await?;

    if operation != context.operation() || request_hash.as_slice() != context.request_hash() {
        return Err(IdempotentClientOperationError::IdempotencyConflict);
    }
    match (inserted, result_data) {
        (true, None) => Ok(Claim::New { secret_kid }),
        (false, Some(Json(result))) => Ok(Claim::Replay { secret_kid, result }),
        _ => Err(IdempotentClientOperationError::CorruptResult),
    }
}

async fn complete_operation<T: serde::Serialize>(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    context: &ClientIdempotencyContext,
    result: &T,
) -> Result<(), IdempotentClientOperationError> {
    let result =
        serde_json::to_value(result).map_err(|_| IdempotentClientOperationError::CorruptResult)?;
    let key_digest = context.key_digest();
    let updated = crate::sqlx::query(
        "UPDATE client_operation_idempotency
         SET result_data = $3, completed_at = NOW()
         WHERE actor_scope = $1 AND key_digest = $2 AND result_data IS NULL",
    )
    .bind(context.actor_scope())
    .bind(key_digest.as_slice())
    .bind(Json(result))
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdempotentClientOperationError::CorruptResult)
    }
}
