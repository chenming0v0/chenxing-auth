//! Durable access-token revocation records (Issue #656).
//!
//! PostgreSQL is the authoritative store; Redis in [`super::revocation`] is a
//! fast-path cache. This module is the only SQL outlet for
//! `revoked_access_tokens`.

use time::OffsetDateTime;

use crate::sqlx::PgPool;

/// SHA-256 digest of an access token. The raw token never reaches this table.
pub(super) type TokenDigest = [u8; 32];

/// PostgreSQL implementation of durable access-token revocation.
#[derive(Clone)]
pub(super) struct PgAccessTokenRevocationRepository {
    pool: PgPool,
}

impl PgAccessTokenRevocationRepository {
    pub(super) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a revocation. Idempotent: repeating the same digest is a no-op.
    ///
    /// `ttl_seconds` is the remaining token lifetime at revoke time. Expiry is
    /// computed from the database clock so reaping and insertion share one
    /// time source.
    pub(super) async fn record(
        &self,
        token_hash: &TokenDigest,
        ttl_seconds: u64,
    ) -> Result<(), crate::sqlx::Error> {
        let ttl = i64::try_from(ttl_seconds.max(1)).unwrap_or(i64::MAX);
        crate::sqlx::query(
            "INSERT INTO revoked_access_tokens (token_hash, expires_at)
             VALUES ($1, NOW() + ($2 * INTERVAL '1 second'))
             ON CONFLICT (token_hash) DO NOTHING",
        )
        .bind(token_hash.as_slice())
        .bind(ttl)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return the stored expiry when the digest is revoked.
    ///
    /// Does not filter on `expires_at`. That column is a reap hint; treating a
    /// still-present row as not-revoked would resurrect a JWT whose `exp` has
    /// not yet elapsed.
    pub(super) async fn lookup(
        &self,
        token_hash: &TokenDigest,
    ) -> Result<Option<OffsetDateTime>, crate::sqlx::Error> {
        crate::sqlx::query_scalar::<_, OffsetDateTime>(
            "SELECT expires_at FROM revoked_access_tokens WHERE token_hash = $1",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
    }

    pub(super) async fn remove(&self, token_hash: &TokenDigest) -> Result<(), crate::sqlx::Error> {
        crate::sqlx::query("DELETE FROM revoked_access_tokens WHERE token_hash = $1")
            .bind(token_hash.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
