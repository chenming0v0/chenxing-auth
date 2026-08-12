use super::{PgPool, UserId};

/// Read the current secret generation for a client in the caller's scope.
///
/// Public clients, disabled clients, and clients outside the requested owner
/// scope deliberately look the same as a missing client to the service layer.
/// `status = 'active'` is the same policy gate the credential-check path
/// enforces (`credentials::constant_time`), so a disabled Client can never be
/// rotated into a fresh valid secret (Issue #416).
pub async fn find_client_secret_version(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
) -> Result<Option<i64>, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT client_secret_version FROM oauth_clients
         WHERE client_id = $1
           AND ($2::bigint IS NULL OR owner_user_id = $2)
           AND auth_method <> 'none'
           AND status = 'active'",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .fetch_optional(pool)
    .await
}

/// Replace a client secret only if the caller still owns the observed version.
///
/// The version predicate and increment are one atomic UPDATE. A false result
/// means that another rotation won the compare-and-swap; no new hash was
/// written by this call.
///
/// `status = 'active'` is repeated here (not only in the read above) so a
/// Client disabled between the version read and this UPDATE — the rotation
/// TOCTOU window — still cannot receive a fresh secret (Issue #416).
pub async fn update_client_secret_if_version(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    expected_version: i64,
    client_secret_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
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
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
