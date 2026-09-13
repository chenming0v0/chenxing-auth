//! Opt-in lifecycle tests for the prepared template database (#710 stage 1).
//!
//! These run only when both template environment variables are present (CI
//! prepares them); with both absent the tests return immediately. A partial or
//! malformed environment fails loudly instead of silently skipping.
//!
//! The suite treats the job template as an immutable source and never runs
//! `db::migrate`. It derives its own `ctest_lifecycle_<hash>_` namespace, clones
//! that child template from the job template, and tracks every database it
//! creates by catalog OID. Cleanup removes only tracked objects (and the owned
//! child namespace); it never touches the job template or a name it did not
//! create. When a scenario and its cleanup both fail, both sanitized failures
//! are reported.
//!
//! A run owns its derived `ctest_lifecycle_<hash>_` namespace exclusively; there
//! is no registry, slot pool, or lock. The test-level finalizer drops only
//! databases tracked by catalog OID; a broad `own.cleanup()` runs only inside
//! the deliberate, catalog-preflighted lookalike scenario.

mod cleanup;
mod helpers;
mod scenarios;
mod tracking;

use cleanup::lookalike_case;
use helpers::{cleanup_owned, job_config, own_config, short_hash};
use scenarios::{admin_search_path_case, clone_isolation_case, unsealed_template_case};

fn report(scenario: Result<(), String>, cleanup: Result<(), String>) {
    match (scenario, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(scenario), Ok(())) => panic!("template lifecycle: {scenario}"),
        (Ok(()), Err(cleanup)) => panic!("template lifecycle cleanup: {cleanup}"),
        (Err(scenario), Err(cleanup)) => {
            panic!("template lifecycle: {scenario}; cleanup also failed: {cleanup}")
        }
    }
}

#[tokio::test]
async fn template_lifecycle_clone_isolation_and_duplicate_rejection() {
    let Some(job) = job_config() else {
        return;
    };
    let identity = "lifecycle_clone_isolation";
    let own = own_config(job.namespace(), identity);
    let mut created = Vec::new();

    let scenario = clone_isolation_case(&job, &own, identity, &mut created).await;
    let cleanup = cleanup_owned(&job, &created).await;
    report(scenario, cleanup);
}

#[tokio::test]
async fn template_lifecycle_cleanup_leaves_lookalikes_untouched() {
    let Some(job) = job_config() else {
        return;
    };
    let identity = "lifecycle_lookalike";
    let own = own_config(job.namespace(), identity);
    let hash = short_hash(&format!("{}\0{identity}", job.namespace().prefix()));
    let sentinels = [
        format!("{}{}_007", own.namespace().prefix(), "0".repeat(16)),
        format!("ctest_other_{hash}_sentinel"),
    ];
    let mut created = Vec::new();

    let scenario = lookalike_case(&job, &own, &sentinels, &mut created).await;
    let cleanup = cleanup_owned(&job, &created).await;
    report(scenario, cleanup);
}

#[tokio::test]
async fn template_lifecycle_unsealed_template_is_rejected() {
    let Some(job) = job_config() else {
        return;
    };
    let identity = "lifecycle_unsealed";
    let own = own_config(job.namespace(), identity);
    let mut created = Vec::new();

    let scenario = unsealed_template_case(&job, &own, identity, &mut created).await;
    let cleanup = cleanup_owned(&job, &created).await;
    report(scenario, cleanup);
}

#[tokio::test]
async fn template_lifecycle_admin_connection_pins_pg_catalog() {
    let Some(job) = job_config() else {
        return;
    };
    // A hostile `search_path` in the URL options must not shadow the admin
    // catalog functions: the fixture pins the admin connection to pg_catalog.
    let scenario = admin_search_path_case(&job).await;
    report(scenario, Ok(()));
}
