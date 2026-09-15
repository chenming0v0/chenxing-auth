//! Deliberate, preflighted namespace cleanup scenario.
//!
//! This is the only place a broad `own.cleanup()` runs. It is preceded by
//! `verify_cleanup_candidates_owned`, which cross-checks the full `pg_database`
//! catalog against the successful-create records before anything is deleted.
//! Lookalike sentinels live outside the namespace grammar and must retain their
//! catalog OID and data. A raw backend on the intended clone is kept alive
//! across cleanup so termination is actually exercised, and a repeated cleanup
//! is preflighted against an empty candidate set.

use chenxing_auth::db::test_timing::Timing;
use chenxing_auth::sqlx::{query, query_scalar};

use crate::db_isolation::template_database::TemplateConfig;

use super::helpers::{
    connect_database, create_child_template, create_sentinel, freeze_child_template, source_names,
};
use super::tracking::{
    CreatedDatabase, catalog_state, record_created, verify_cleanup_candidates_owned,
};

pub(super) async fn lookalike_case(
    job: &TemplateConfig,
    own: &TemplateConfig,
    sentinels: &[String],
    created: &mut Vec<CreatedDatabase>,
) -> Result<(), String> {
    let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
    create_child_template(&mut owner, own, job, created).await?;
    freeze_child_template(&mut owner, own).await?;
    drop(owner);

    let sources = source_names(job);
    for name in sentinels {
        let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
        create_sentinel(
            &mut owner,
            own.namespace(),
            job.namespace(),
            name,
            &sources,
            created,
        )
        .await?;
        let mut connection = connect_database(job, name).await?;
        query("CREATE TABLE sentinel_data (id integer)")
            .execute(&mut connection)
            .await
            .map_err(|_| "sentinel is not writeable".to_owned())?;
        query("INSERT INTO sentinel_data (id) VALUES (1)")
            .execute(&mut connection)
            .await
            .map_err(|_| "sentinel insert failed".to_owned())?;
        drop(connection);
    }

    let pid = std::process::id();
    let mut timing = Timing::disabled();
    let pool = own
        .clone_pool("lifecycle", "lookalike", pid, 2, &mut timing)
        .await
        .map_err(|e| e.to_string())?;
    let clone_name = own
        .namespace()
        .clone_name("lifecycle", "lookalike", pid)
        .map_err(|e| e.to_string())?;
    {
        let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
        created.push(record_created(&mut owner, clone_name.as_str()).await?);
    }

    // Keep a raw backend on the intended clone alive across cleanup so the
    // termination path is actually exercised; the pool handles are closed first
    // so cleanup cannot reacquire them later.
    let mut raw = connect_database(own, clone_name.as_str()).await?;
    pool.close().await;

    // Deliberate normal cleanup, preflighted against the full catalog and the
    // successful-create records before anything is deleted.
    let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
    verify_cleanup_candidates_owned(&mut owner, own.namespace(), created, true).await?;

    let summary = own.cleanup().await.map_err(|e| e.to_string())?;
    if summary.clones_dropped != 1 || summary.templates_dropped != 1 {
        return Err(format!(
            "cleanup dropped {} clone(s) and {} template(s), expected one of each",
            summary.clones_dropped, summary.templates_dropped
        ));
    }

    // The raw backend must now be gone: cleanup terminated it and dropped the
    // clone from the catalog.
    if query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&mut raw)
        .await
        .is_ok()
    {
        return Err("cleanup left a live backend on the intended clone".to_owned());
    }
    drop(raw);

    // Both owned candidates must be gone from the catalog.
    for name in [clone_name.as_str(), own.template_name().as_str()] {
        if catalog_state(&mut owner, name).await?.is_some() {
            return Err("cleanup left a catalog entry behind".to_owned());
        }
    }

    // A repeated cleanup is preflighted against an empty candidate set and must
    // succeed without deleting anything else.
    verify_cleanup_candidates_owned(&mut owner, own.namespace(), created, false).await?;
    let again = own.cleanup().await.map_err(|e| e.to_string())?;
    if again.clones_dropped != 0 || again.templates_dropped != 0 {
        return Err("repeated cleanup was not a no-op".to_owned());
    }

    // Sentinels must keep the exact catalog OID and their data.
    for recorded in created
        .iter()
        .filter(|object| sentinels.iter().any(|name| name == &object.name))
    {
        let state = catalog_state(&mut owner, &recorded.name).await?;
        let Some((oid, owner_oid, datistemplate)) = state else {
            return Err("cleanup removed a lookalike database".to_owned());
        };
        if oid != recorded.oid {
            return Err("cleanup replaced a lookalike database".to_owned());
        }
        if datistemplate || owner_oid != recorded.owner_oid {
            return Err("lookalike catalog state changed".to_owned());
        }
        let mut connection = connect_database(job, &recorded.name).await?;
        let count: i64 = query_scalar("SELECT count(*) FROM sentinel_data")
            .fetch_one(&mut connection)
            .await
            .map_err(|_| "read sentinel data failed".to_owned())?;
        if count != 1 {
            return Err("cleanup modified lookalike data".to_owned());
        }
    }
    Ok(())
}
