//! Template cloning for the fixture (#710 stage 1).
//!
//! `clone_pool` never falls back to a schema fixture: a missing template,
//! missing permissions, or a mismatched configuration fails the invocation. It
//! records the first three fixture phases and leaves the final sequence phase
//! to the enclosing fixture.

use chenxing_auth::db::test_timing::{self, Timing};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::sqlx::{PgConnection, PgPool, query, query_as, query_scalar};

use super::config::TemplateConfig;
use super::error::{DbTestError, database_error};
use super::names::{DatabaseName, quote_identifier};

impl TemplateConfig {
    /// Clone the namespace template and return a pool scoped to the new copy.
    ///
    /// Records `bootstrap_connection`, `database_clone`, and `pool_connect` on
    /// `timing` (including on failure). The clone name is deterministic per
    /// `(binary_label, identity, pid)`, and the `CREATE DATABASE` has no
    /// `IF NOT EXISTS`, so a duplicate create fails loudly.
    pub async fn clone_pool(
        &self,
        binary_label: &str,
        identity: &str,
        pid: u32,
        max_connections: u32,
        timing: &mut Timing,
    ) -> Result<PgPool, DbTestError> {
        let clone = self.namespace().clone_name(binary_label, identity, pid)?;

        let phase = timing.phase_start();
        let connection = match self.owner_connection().await {
            Ok(connection) => {
                timing.record(test_timing::PHASE_BOOTSTRAP_CONNECTION, phase);
                connection
            }
            Err(error) => {
                timing.record(test_timing::PHASE_BOOTSTRAP_CONNECTION, phase);
                return Err(error);
            }
        };

        let phase = timing.phase_start();
        let created = self.create_clone(connection, &clone).await;
        timing.record(test_timing::PHASE_DATABASE_CLONE, phase);
        created?;

        let phase = timing.phase_start();
        let connected = self.connect_pool_to(&clone, max_connections).await;
        timing.record(test_timing::PHASE_POOL_CONNECT, phase);
        let pool = connected?;

        // The pool must point at the clone, never the source or template, and
        // every connection must resolve to the public schema.
        let current: String = query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .map_err(|error| database_error("read clone database", &error))?;
        if current != clone.as_str() {
            return Err(DbTestError::PoolInvariant("current_database"));
        }
        let schema: String = query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .map_err(|error| database_error("read clone schema", &error))?;
        if schema != "public" {
            return Err(DbTestError::PoolInvariant("current_schema"));
        }
        Ok(pool)
    }

    /// Build a pool for `database` with a per-connection `public` search path.
    pub(super) async fn connect_pool_to(
        &self,
        database: &DatabaseName,
        max_connections: u32,
    ) -> Result<PgPool, DbTestError> {
        let options = self.owner_options_for(database.as_str())?;
        PgPoolOptions::new()
            .max_connections(max_connections)
            .after_connect(|connection, _meta| {
                Box::pin(async move {
                    query("SET search_path TO public")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(|error| database_error("connect pool", &error))
    }

    /// Verify the namespace template is sealed and ready to clone.
    ///
    /// Checks the exact catalog state before any `CREATE DATABASE`: the current
    /// session role owns the template, it is not a PostgreSQL template, and it
    /// does not accept connections (`datallowconn = false`). This rejects a
    /// partially prepared, still-open template instead of cloning it. Generic
    /// cleanup deliberately does not require `datallowconn = false`, so a
    /// half-prepared template can still be removed.
    pub(crate) async fn verify_template_sealed(
        &self,
        connection: &mut PgConnection,
    ) -> Result<(), DbTestError> {
        let template = self.namespace().template_name();

        let role_oid: i64 = query_scalar(
            "SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname = session_user",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database_error("read role oid", &error))?;

        let row: Option<(i64, bool, bool)> = query_as::<_, (i64, bool, bool)>(
            "SELECT datdba::bigint, datistemplate, datallowconn \
             FROM pg_catalog.pg_database WHERE datname = $1",
        )
        .bind(template.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| database_error("read template state", &error))?;

        let Some((owner_oid, datistemplate, datallowconn)) = row else {
            return Err(DbTestError::NameCollision("template is not prepared"));
        };
        if datistemplate {
            return Err(DbTestError::ProtectedDatabase);
        }
        if owner_oid != role_oid {
            return Err(DbTestError::RoleNotOwner("template"));
        }
        if datallowconn {
            return Err(DbTestError::SourceMismatch("template is not sealed"));
        }
        Ok(())
    }

    async fn create_clone(
        &self,
        mut connection: PgConnection,
        clone: &DatabaseName,
    ) -> Result<(), DbTestError> {
        // The template must be owned, non-template, and sealed before mutating.
        self.verify_template_sealed(&mut connection).await?;
        // No IF NOT EXISTS: a duplicate create must fail loudly.
        let statement = format!(
            "CREATE DATABASE {} TEMPLATE {}",
            quote_identifier(clone.as_str()),
            quote_identifier(self.namespace().template_name().as_str())
        );
        query(statement.as_str())
            .execute(&mut connection)
            .await
            .map_err(|error| database_error("create clone", &error))?;
        Ok(())
    }
}
