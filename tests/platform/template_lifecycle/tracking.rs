//! OID-tracked database creation and cleanup for the lifecycle tests.
//!
//! The lifecycle suite only ever removes databases this invocation actually
//! created: each successful `CREATE DATABASE` records the catalog OID and owner
//! OID, and deletion re-reads the catalog and refuses to act if the name now
//! points at a different OID (a replaced database), a template, or a different
//! owner. No name is ever dropped unconditionally, and no cleanup error is
//! swallowed.

use std::time::Duration;

use chenxing_auth::sqlx::{PgConnection, query, query_as, query_scalar};

use crate::db_isolation::template_database::Namespace;
use crate::db_isolation::template_database::names::quote_identifier;

/// A database this invocation created, with the catalog identity needed to
/// delete it safely later.
#[derive(Debug, Clone)]
pub(super) struct CreatedDatabase {
    pub(super) name: String,
    pub(super) oid: i64,
    pub(super) owner_oid: i64,
}

/// Read the catalog identity of a just-created database.
pub(super) async fn record_created(
    connection: &mut PgConnection,
    name: &str,
) -> Result<CreatedDatabase, String> {
    let row = catalog_state(connection, name).await?;
    let Some((oid, owner_oid, datistemplate)) = row else {
        return Err("created database is missing from the catalog".to_owned());
    };
    if datistemplate {
        return Err("created database is a template".to_owned());
    }
    Ok(CreatedDatabase {
        name: name.to_owned(),
        oid,
        owner_oid,
    })
}

/// Drop every tracked database that is still the exact recorded catalog object.
///
/// Absent names are skipped (idempotent). A name whose OID, template flag, or
/// owner changed since creation is reported and left untouched; the remaining
/// owned targets are still cleaned so an ordinary failure does not strand them.
pub(super) async fn drop_tracked(
    connection: &mut PgConnection,
    tracked: &[CreatedDatabase],
) -> Result<u32, String> {
    let mut dropped = 0;
    let mut errors = Vec::new();
    for object in tracked {
        let Some((oid, owner_oid, datistemplate)) = catalog_state(connection, &object.name).await?
        else {
            continue;
        };
        if oid != object.oid {
            errors.push("tracked database was replaced; left untouched".to_owned());
            continue;
        }
        if datistemplate {
            errors.push("tracked database became a template; left untouched".to_owned());
            continue;
        }
        if owner_oid != object.owner_oid {
            errors.push("tracked database owner changed; left untouched".to_owned());
            continue;
        }
        match drop_database(connection, &object.name).await {
            Ok(()) => dropped += 1,
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(dropped)
    } else {
        Err(errors.join("; "))
    }
}

pub(super) async fn catalog_state(
    connection: &mut PgConnection,
    name: &str,
) -> Result<Option<(i64, i64, bool)>, String> {
    query_as::<_, (i64, i64, bool)>(
        "SELECT oid::bigint, datdba::bigint, datistemplate \
         FROM pg_catalog.pg_database WHERE datname = $1",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| "read database catalog state failed".to_owned())
}

/// Every own-namespace cleanup candidate must be registered and unchanged.
///
/// Reads the full `pg_database` catalog, keeps only rows whose name matches the
/// exact own namespace grammar (the template name or a clone), and rejects any
/// candidate that was not recorded on a successful `CREATE DATABASE` or whose
/// OID, owner OID, or template flag no longer matches its record. With
/// `require_tracked_present`, every recorded candidate must still be present
/// with the same OID, so a replaced identity is caught before any deletion.
/// Lookalike sentinels are outside the namespace grammar and are never
/// candidates. This runs before a deliberate `own.cleanup()`; it never mutates.
pub(super) async fn verify_cleanup_candidates_owned(
    connection: &mut PgConnection,
    namespace: &Namespace,
    tracked: &[CreatedDatabase],
    require_tracked_present: bool,
) -> Result<(), String> {
    let rows: Vec<(String, i64, i64, bool)> = query_as::<_, (String, i64, i64, bool)>(
        "SELECT datname::text, oid::bigint, datdba::bigint, datistemplate \
         FROM pg_catalog.pg_database",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| "list database catalog failed".to_owned())?;

    let template = namespace.template_name().as_str();
    let is_candidate_name = |name: &str| name == template || namespace.is_copy_name(name);

    for (name, oid, owner_oid, datistemplate) in &rows {
        if !is_candidate_name(name) {
            continue;
        }
        let Some(record) = tracked.iter().find(|record| &record.name == name) else {
            return Err("cleanup candidate is not registered by a successful create".to_owned());
        };
        if record.oid != *oid || record.owner_oid != *owner_oid || *datistemplate {
            return Err("cleanup candidate identity does not match its record".to_owned());
        }
    }

    if require_tracked_present {
        for record in tracked {
            if !is_candidate_name(&record.name) {
                continue;
            }
            let present = rows
                .iter()
                .any(|(name, oid, _, _)| name == &record.name && *oid == record.oid);
            if !present {
                return Err("recorded cleanup candidate is missing before cleanup".to_owned());
            }
        }
    }
    Ok(())
}

async fn drop_database(connection: &mut PgConnection, name: &str) -> Result<(), String> {
    let disallow = format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS false",
        quote_identifier(name)
    );
    query(disallow.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|_| "disallow connections failed".to_owned())?;

    query(
        "SELECT pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(name)
    .execute(&mut *connection)
    .await
    .map_err(|_| "terminate sessions failed".to_owned())?;

    let mut remaining = i64::MAX;
    for _ in 0..50 {
        remaining = query_scalar(
            "SELECT count(*)::bigint FROM pg_catalog.pg_stat_activity WHERE datname = $1",
        )
        .bind(name)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| "confirm termination failed".to_owned())?;
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if remaining != 0 {
        return Err("sessions remained on a tracked database".to_owned());
    }

    let drop_statement = format!("DROP DATABASE {}", quote_identifier(name));
    query(drop_statement.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|_| "drop database failed".to_owned())?;
    Ok(())
}
