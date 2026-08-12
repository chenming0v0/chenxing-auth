//! Client credential snapshots and the persistence fence used by token issuance.

use std::fmt;

use crate::sqlx::PgPool;

pub struct StoredClientCredentials {
    pub client_secret_hash: Option<String>,
    pub auth_method: String,
    pub status: String,
    /// Version read in the same snapshot as the hash it authenticates.
    pub client_secret_version: i64,
    /// Compatibility bit for Refresh Tokens serialized before version binding.
    pub allow_legacy_refresh_tokens: bool,
}

impl fmt::Debug for StoredClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredClientCredentials")
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("auth_method", &self.auth_method)
            .field("status", &self.status)
            .field("client_secret_version", &self.client_secret_version)
            .field(
                "allow_legacy_refresh_tokens",
                &self.allow_legacy_refresh_tokens,
            )
            .finish()
    }
}

/// Read the hash and every policy value that belongs to the same authentication
/// snapshot. Callers must not re-read the version after Argon2 verification.
pub async fn find_client_credentials(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClientCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Option<String>, String, String, i64, bool)>(
        "SELECT client_secret_hash, auth_method, status, client_secret_version,
                allow_legacy_refresh_tokens
         FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(
            |(
                client_secret_hash,
                auth_method,
                status,
                client_secret_version,
                allow_legacy_refresh_tokens,
            )| StoredClientCredentials {
                client_secret_hash,
                auth_method,
                status,
                client_secret_version,
                allow_legacy_refresh_tokens,
            },
        )
    })
}

/// Lock a Client credential row for a refresh-token persistence decision.
///
/// `FOR SHARE` allows concurrent token issuers for the same Client, but conflicts
/// with the row lock taken by the secret-rotation `UPDATE`. The caller must keep
/// the surrounding transaction open until its Redis save/rotation has finished.
/// Consequently either the credential write is indexed before secret rotation
/// can commit, or a post-rotation issuer observes a version mismatch and writes
/// nothing.
pub async fn lock_client_credentials_if_version(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    client_id: &str,
    expected_version: i64,
    allow_legacy_refresh_tokens: bool,
) -> Result<bool, crate::sqlx::Error> {
    let current = crate::sqlx::query_scalar(
        "SELECT status = 'active'
                AND client_secret_version = $2
                AND allow_legacy_refresh_tokens = $3
         FROM oauth_clients
         WHERE client_id = $1
         FOR SHARE",
    )
    .bind(client_id)
    .bind(expected_version)
    .bind(allow_legacy_refresh_tokens)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(current == Some(true))
}
