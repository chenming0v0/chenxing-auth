//! Scenario bodies for the opt-in template lifecycle tests.
//!
//! Each `run_*` returns a sanitized failure string on the first problem; the
//! caller is responsible for OID-tracked cleanup and for reporting scenario and
//! cleanup failures together. The one deliberate namespace cleanup lives in
//! `super::cleanup`.

use chenxing_auth::db::test_timing::Timing;
use chenxing_auth::sqlx::{Connection, PgConnection, query, query_scalar};

use crate::db_isolation::template_database::{DbTestError, OWNER_DATABASE_URL_ENV, TemplateConfig};

use super::helpers::{assert_connection_matches, create_child_template, freeze_child_template};
use super::tracking::{CreatedDatabase, record_created};

pub(super) async fn clone_isolation_case(
    job: &TemplateConfig,
    own: &TemplateConfig,
    identity: &str,
    created: &mut Vec<CreatedDatabase>,
) -> Result<(), String> {
    let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
    create_child_template(&mut owner, own, job, created).await?;
    freeze_child_template(&mut owner, own).await?;
    drop(owner);

    // The frozen job template must reject direct connections, so it cannot be
    // accidentally migrated or used as a live fixture.
    let job_options = job
        .owner_options_for(job.template_name().as_str())
        .map_err(|e| e.to_string())?;
    if PgConnection::connect_with(&job_options).await.is_ok() {
        return Err("prepared job template accepted a connection".to_owned());
    }

    let pid = std::process::id();
    let mut timing = Timing::disabled();
    let pool = own
        .clone_pool("lifecycle", identity, pid, 2, &mut timing)
        .await
        .map_err(|e| e.to_string())?;
    let clone_name = own
        .namespace()
        .clone_name("lifecycle", identity, pid)
        .map_err(|e| e.to_string())?;
    {
        let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
        created.push(record_created(&mut owner, clone_name.as_str()).await?);
    }

    // Both checked-out connections must resolve to the clone and to `public`.
    let mut first = pool
        .acquire()
        .await
        .map_err(|_| "acquire clone connection failed".to_owned())?;
    let mut second = pool
        .acquire()
        .await
        .map_err(|_| "acquire clone connection failed".to_owned())?;
    assert_connection_matches(&mut first, clone_name.as_str()).await?;
    assert_connection_matches(&mut second, clone_name.as_str()).await?;
    drop(first);
    drop(second);

    // The clone is writeable and shares nothing with independent siblings.
    query("CREATE TABLE lifecycle_sentinel (id integer)")
        .execute(&pool)
        .await
        .map_err(|_| "clone is not writeable".to_owned())?;
    query("INSERT INTO lifecycle_sentinel (id) VALUES (1)")
        .execute(&pool)
        .await
        .map_err(|_| "clone insert failed".to_owned())?;

    let other_pid = pid.wrapping_add(1).max(1);
    let other = own
        .clone_pool("lifecycle", identity, other_pid, 2, &mut timing)
        .await
        .map_err(|e| e.to_string())?;
    let other_name = own
        .namespace()
        .clone_name("lifecycle", identity, other_pid)
        .map_err(|e| e.to_string())?;
    {
        let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
        created.push(record_created(&mut owner, other_name.as_str()).await?);
    }
    let sibling_sentinel: Option<String> =
        query_scalar("SELECT to_regclass('public.lifecycle_sentinel')::text")
            .fetch_one(&other)
            .await
            .map_err(|_| "read sibling relation failed".to_owned())?;
    if sibling_sentinel.is_some() {
        return Err("clones share data instead of being independent copies".to_owned());
    }
    other.close().await;

    // A duplicate create must fail with 42P04 from `CREATE DATABASE`, and the
    // existing clone must keep its data.
    match own
        .clone_pool("lifecycle", identity, pid, 2, &mut timing)
        .await
    {
        Ok(_) => return Err("duplicate clone creation succeeded".to_owned()),
        Err(DbTestError::DatabaseOperation {
            operation: "create clone",
            sqlstate,
        }) if sqlstate.as_deref() == Some("42P04") => {}
        Err(other) => return Err(format!("duplicate clone error was {other}")),
    }
    let count: i64 = query_scalar("SELECT count(*) FROM lifecycle_sentinel")
        .fetch_one(&pool)
        .await
        .map_err(|_| "read sentinel failed".to_owned())?;
    if count != 1 {
        return Err("duplicate attempt damaged the existing clone".to_owned());
    }

    pool.close().await;
    Ok(())
}

pub(super) async fn unsealed_template_case(
    job: &TemplateConfig,
    own: &TemplateConfig,
    identity: &str,
    created: &mut Vec<CreatedDatabase>,
) -> Result<(), String> {
    let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
    create_child_template(&mut owner, own, job, created).await?;
    // Deliberately not frozen: `datallowconn` is still true.
    drop(owner);

    let pid = std::process::id();
    let mut timing = Timing::disabled();
    match own
        .clone_pool("lifecycle", identity, pid, 2, &mut timing)
        .await
    {
        Ok(_) => return Err("cloning an unsealed template succeeded".to_owned()),
        Err(DbTestError::SourceMismatch(_)) => {}
        Err(other) => return Err(format!("unsealed clone error was {other}")),
    }

    let clone_name = own
        .namespace()
        .clone_name("lifecycle", identity, pid)
        .map_err(|e| e.to_string())?;
    let mut owner = job.owner_connection().await.map_err(|e| e.to_string())?;
    let exists: bool =
        query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)")
            .bind(clone_name.as_str())
            .fetch_one(&mut owner)
            .await
            .map_err(|_| "check clone target failed".to_owned())?;
    if exists {
        return Err("unsealed template created a clone target".to_owned());
    }
    Ok(())
}

/// Build a hostile owner URL and prove the admin connection still pins
/// `pg_catalog` before its identity/catalog queries run.
pub(super) async fn admin_search_path_case(job: &TemplateConfig) -> Result<(), String> {
    let owner_url =
        std::env::var(OWNER_DATABASE_URL_ENV).map_err(|_| "missing owner URL".to_owned())?;
    let mut hostile =
        url::Url::parse(&owner_url).map_err(|_| "owner URL did not parse".to_owned())?;
    hostile
        .query_pairs_mut()
        .append_pair("options", "-c search_path=public,pg_catalog");
    let config = TemplateConfig::from_values(job.namespace().clone(), hostile.as_str(), None)
        .map_err(|e| e.to_string())?;

    let mut connection = config.owner_connection().await.map_err(|e| e.to_string())?;
    let schema: String = query_scalar("SELECT current_schema()")
        .fetch_one(&mut connection)
        .await
        .map_err(|_| "read admin current_schema failed".to_owned())?;
    if schema != "pg_catalog" {
        return Err(format!("admin connection resolved to schema {schema}"));
    }
    let database: String = query_scalar("SELECT current_database()")
        .fetch_one(&mut connection)
        .await
        .map_err(|_| "read admin current_database failed".to_owned())?;
    if database.is_empty() {
        return Err("admin connection lost its database".to_owned());
    }
    Ok(())
}
