//! Database lifecycle for the template fixture: prepare and cleanup.
//!
//! Every SQL identifier goes through [`super::names::quote_identifier`]; no
//! unvalidated name is interpolated. The cleanup plan is validated in full
//! (existence, protection, and exact role ownership) before anything is
//! mutated, and clones are dropped before the template.

use std::fmt;
use std::time::Duration;

use chenxing_auth::sqlx::{Connection, PgConnection, query, query_as, query_scalar};

use super::config::TemplateConfig;
use super::error::{DbTestError, database_error};
use super::names::{DatabaseName, quote_identifier};

/// Outcome counts for one cleanup command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupSummary {
    /// Clone databases dropped by this cleanup.
    pub clones_dropped: u32,
    /// Template databases dropped by this cleanup.
    pub templates_dropped: u32,
    /// Known targets that were already absent (idempotent cleanup).
    pub already_absent: u32,
}

impl fmt::Display for CleanupSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "template cleanup: clones_dropped={} templates_dropped={} already_absent={}",
            self.clones_dropped, self.templates_dropped, self.already_absent
        )
    }
}

pub(super) struct CleanupPlan {
    pub(super) clones: Vec<DatabaseName>,
    pub(super) template: Option<DatabaseName>,
}

impl TemplateConfig {
    /// Open a connection to the configured owner source database and verify it.
    ///
    /// Fails unless `current_database()` matches the database named by the
    /// owner URL and `session_user = current_user`.
    pub async fn owner_connection(&self) -> Result<PgConnection, DbTestError> {
        let options = self.owner_options_for(self.source_name().as_str())?;
        let mut connection = PgConnection::connect_with(&options)
            .await
            .map_err(|error| database_error("connect owner", &error))?;

        // A caller-supplied `options=-c search_path=...` in the URL could put a
        // writable schema ahead of pg_catalog and shadow current_database,
        // pg_terminate_backend, pg_backend_pid, and friends. Pin the admin
        // connection to pg_catalog before any identity or catalog query. The
        // template and clone pools are separate and stay on `public`.
        query("SET search_path TO pg_catalog")
            .execute(&mut connection)
            .await
            .map_err(|error| database_error("pin admin search_path", &error))?;

        let current: String = query_scalar("SELECT current_database()")
            .fetch_one(&mut connection)
            .await
            .map_err(|error| database_error("read current_database", &error))?;
        if current != self.source_name().as_str() {
            return Err(DbTestError::SourceMismatch("current_database"));
        }

        let same_role: bool = query_scalar("SELECT session_user = current_user")
            .fetch_one(&mut connection)
            .await
            .map_err(|error| database_error("read session role", &error))?;
        if !same_role {
            return Err(DbTestError::SourceMismatch("session_user/current_user"));
        }
        Ok(connection)
    }

    /// Create and migrate the namespace template, then freeze it.
    ///
    /// The template is created from `template0` with a plain `CREATE DATABASE`
    /// (no `IF NOT EXISTS`), migrated exactly once with a `public` search path,
    /// and finally frozen with `ALLOW_CONNECTIONS false` after confirming that
    /// no sessions remain.
    pub async fn prepare(&self) -> Result<(), DbTestError> {
        let mut connection = self.owner_connection().await?;
        let template_name = self.namespace().template_name();
        let template = template_name.as_str();

        let can_create: bool = query_scalar(
            "SELECT rolcreatedb FROM pg_catalog.pg_roles WHERE rolname = session_user",
        )
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database_error("read CREATEDB", &error))?;
        if !can_create {
            return Err(DbTestError::RoleNotOwner("CREATEDB"));
        }

        let exists: bool =
            query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)")
                .bind(template)
                .fetch_one(&mut connection)
                .await
                .map_err(|error| database_error("check template", &error))?;
        if exists {
            return Err(DbTestError::NameCollision("template already exists"));
        }

        // Validate the complete cleanup plan before the first mutation.
        let _ = self.cleanup_plan(&mut connection).await?;

        let statement = format!(
            "CREATE DATABASE {} TEMPLATE template0",
            quote_identifier(template)
        );
        query(statement.as_str())
            .execute(&mut connection)
            .await
            .map_err(|error| database_error("create template", &error))?;

        let pool = self.connect_pool_to(template_name, 1).await?;
        let migration = chenxing_auth::db::migrate(&pool);
        let result = chenxing_auth::db::test_timing::without_migration_diagnostics(migration).await;
        // Close the template pool even when migration failed.
        pool.close().await;
        result.map_err(|_| DbTestError::DatabaseOperation {
            operation: "migrate template",
            sqlstate: None,
        })?;

        let statement = format!(
            "ALTER DATABASE {} ALLOW_CONNECTIONS false",
            quote_identifier(template)
        );
        query(statement.as_str())
            .execute(&mut connection)
            .await
            .map_err(|error| database_error("freeze template", &error))?;

        let remaining: i64 = query_scalar(
            "SELECT count(*)::bigint FROM pg_catalog.pg_stat_activity WHERE datname = $1",
        )
        .bind(template)
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database_error("confirm template frozen", &error))?;
        if remaining != 0 {
            return Err(DbTestError::SessionsRemain("template"));
        }
        Ok(())
    }

    /// Drop every validated clone in the namespace, then the template.
    ///
    /// The caller owns an exclusive namespace for the duration of a run: there
    /// is no registry, slot pool, or cross-process lock, so cleanup removes all
    /// valid clones and the template under this prefix. It still validates every
    /// candidate's owner and template flag before dropping anything, and generic
    /// cleanup deliberately does not require the template to be sealed, so a
    /// partially prepared template is removed too.
    pub async fn cleanup(&self) -> Result<CleanupSummary, DbTestError> {
        let mut connection = self.owner_connection().await?;
        let plan = self.cleanup_plan(&mut connection).await?;

        let mut summary = CleanupSummary {
            already_absent: u32::from(plan.template.is_none()),
            ..CleanupSummary::default()
        };
        for clone in &plan.clones {
            self.drop_target(&mut connection, clone, &mut summary, true)
                .await?;
        }
        if let Some(template) = &plan.template {
            self.drop_target(&mut connection, template, &mut summary, false)
                .await?;
        }
        Ok(summary)
    }

    /// List the owned clones and, if present, the owned template.
    ///
    /// Fails before any mutation when a candidate is not owned by the exact
    /// session role, or is a database template.
    pub(super) async fn cleanup_plan(
        &self,
        connection: &mut PgConnection,
    ) -> Result<CleanupPlan, DbTestError> {
        let role_oid: i64 = query_scalar(
            "SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname = session_user",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database_error("read role oid", &error))?;

        let rows: Vec<(String, i64, bool)> = query_as::<_, (String, i64, bool)>(
            "SELECT datname::text, datdba::bigint, datistemplate \
             FROM pg_catalog.pg_database",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| database_error("list databases", &error))?;

        let template = self.namespace().template_name().as_str();
        let mut plan = CleanupPlan {
            clones: Vec::new(),
            template: None,
        };
        for (name, owner, datistemplate) in rows {
            let is_clone = self.namespace().is_copy_name(&name);
            let is_our_template = name == template;
            if !is_clone && !is_our_template {
                continue;
            }
            if datistemplate {
                return Err(DbTestError::ProtectedDatabase);
            }
            if owner != role_oid {
                return Err(DbTestError::RoleNotOwner(if is_clone {
                    "clone candidate"
                } else {
                    "template"
                }));
            }
            let validated = DatabaseName::new_validated(&name)?;
            if is_clone {
                plan.clones.push(validated);
            } else {
                plan.template = Some(validated);
            }
        }
        Ok(plan)
    }

    async fn drop_target(
        &self,
        connection: &mut PgConnection,
        name: &DatabaseName,
        summary: &mut CleanupSummary,
        is_clone: bool,
    ) -> Result<(), DbTestError> {
        let quoted = quote_identifier(name.as_str());
        let statement = format!("ALTER DATABASE {quoted} ALLOW_CONNECTIONS false");
        query(statement.as_str())
            .execute(&mut *connection)
            .await
            .map_err(|error| database_error("disallow connections", &error))?;

        // Terminate only backends bound to this exact datname.
        query(
            "SELECT pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(name.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|error| database_error("terminate sessions", &error))?;

        // Confirm termination with a bounded wait.
        let mut remaining = i64::MAX;
        for _ in 0..50 {
            remaining = query_scalar(
                "SELECT count(*)::bigint FROM pg_catalog.pg_stat_activity WHERE datname = $1",
            )
            .bind(name.as_str())
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| database_error("confirm termination", &error))?;
            if remaining == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if remaining != 0 {
            return Err(DbTestError::SessionsRemain("cleanup target"));
        }

        let statement = format!("DROP DATABASE {quoted}");
        query(statement.as_str())
            .execute(&mut *connection)
            .await
            .map_err(|error| database_error("drop database", &error))?;
        if is_clone {
            summary.clones_dropped += 1;
        } else {
            summary.templates_dropped += 1;
        }
        Ok(())
    }
}
