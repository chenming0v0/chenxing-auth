//! Local helpers for the opt-in template lifecycle tests.
//!
//! The suite treats the job template as an immutable source, clones a child
//! template from it inside a derived `ctest_lifecycle_<hash>_` namespace, and
//! tracks every database it creates by catalog OID. It never runs `db::migrate`
//! and never cleans the job template.

use chenxing_auth::sqlx::{Connection, PgConnection, query, query_scalar};
use sha2::{Digest, Sha256};

use crate::db_isolation::template_database::names::quote_identifier;
use crate::db_isolation::template_database::{
    DATABASE_PREFIX_ENV, Namespace, OWNER_DATABASE_URL_ENV, RUNTIME_DATABASE_URL_ENV,
    TEMPLATE_DATABASE_ENV, TemplateConfig,
};

use super::tracking::{CreatedDatabase, drop_tracked, record_created};

/// The job configuration, or `None` when both template variables are absent.
///
/// A partial or malformed environment fails loudly instead of silently
/// skipping, so a misconfigured CI run cannot pass without exercising anything.
pub(super) fn job_config() -> Option<TemplateConfig> {
    let template = std::env::var(TEMPLATE_DATABASE_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let prefix = std::env::var(DATABASE_PREFIX_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    match (template.is_some(), prefix.is_some()) {
        (false, false) => None,
        (true, true) => Some(TemplateConfig::from_env().expect("valid template environment")),
        _ => panic!(
            "CHENXING_TEST_TEMPLATE_DATABASE and CHENXING_TEST_DATABASE_PREFIX must both be set"
        ),
    }
}

/// Build the configuration for this suite's own derived child namespace.
pub(super) fn own_config(job: &Namespace, identity: &str) -> TemplateConfig {
    let owner_url = std::env::var(OWNER_DATABASE_URL_ENV).expect("owner URL");
    let runtime_url = std::env::var(RUNTIME_DATABASE_URL_ENV).ok();
    TemplateConfig::from_values(
        lifecycle_namespace(job, identity),
        &owner_url,
        runtime_url.as_deref(),
    )
    .expect("own lifecycle config")
}

pub(super) fn short_hash(seed: &str) -> String {
    Sha256::digest(seed.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `ctest_lifecycle_` (16) + 16 hex + `_` = 33 bytes, within 12..=36.
fn lifecycle_namespace(job: &Namespace, identity: &str) -> Namespace {
    let hash = short_hash(&format!("{}\0{identity}", job.prefix()));
    let prefix = format!("ctest_lifecycle_{hash}_");
    let template = format!("{prefix}template");
    Namespace::new(&template, &prefix).expect("derived lifecycle namespace")
}

/// The configured owner and runtime source database names, never to be created
/// or dropped by this suite.
pub(super) fn source_names(job: &TemplateConfig) -> Vec<String> {
    let mut names = vec![job.source_name().as_str().to_owned()];
    if let Some(runtime) = std::env::var(RUNTIME_DATABASE_URL_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        && let Ok(parsed) = job.validate_source_url(&runtime)
    {
        names.push(parsed.as_str().to_owned());
    }
    names
}

/// Create the child template from the frozen job template, recording its OID.
///
/// Reuses the shared sealed-template check so a partially prepared job template
/// is rejected before any mutation, and `CREATE DATABASE` fails if the child
/// name already exists (there is no `IF NOT EXISTS` and no pre-creation drop).
pub(super) async fn create_child_template(
    owner: &mut PgConnection,
    own: &TemplateConfig,
    job: &TemplateConfig,
    created: &mut Vec<CreatedDatabase>,
) -> Result<(), String> {
    job.verify_template_sealed(&mut *owner)
        .await
        .map_err(|error| error.to_string())?;
    let statement = format!(
        "CREATE DATABASE {} TEMPLATE {}",
        quote_identifier(own.template_name().as_str()),
        quote_identifier(job.template_name().as_str())
    );
    query(statement.as_str())
        .execute(&mut *owner)
        .await
        .map_err(|_| "create lifecycle template failed".to_owned())?;
    created.push(record_created(&mut *owner, own.template_name().as_str()).await?);
    Ok(())
}

/// Freeze the child template and confirm the catalog now reports it sealed.
pub(super) async fn freeze_child_template(
    owner: &mut PgConnection,
    own: &TemplateConfig,
) -> Result<(), String> {
    let statement = format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS false",
        quote_identifier(own.template_name().as_str())
    );
    query(statement.as_str())
        .execute(&mut *owner)
        .await
        .map_err(|_| "freeze lifecycle template failed".to_owned())?;
    own.verify_template_sealed(&mut *owner)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Create a sentinel database that must survive the child namespace cleanup.
///
/// The name is refused if it equals a configured source, belongs to the job or
/// own namespace, or already exists. Only a successful create is tracked.
pub(super) async fn create_sentinel(
    owner: &mut PgConnection,
    own: &Namespace,
    job: &Namespace,
    name: &str,
    sources: &[String],
    created: &mut Vec<CreatedDatabase>,
) -> Result<(), String> {
    if sources.iter().any(|source| source == name) {
        return Err("sentinel name collides with a configured source database".to_owned());
    }
    if name == own.template_name().as_str()
        || own.is_copy_name(name)
        || name == job.template_name().as_str()
        || job.is_copy_name(name)
    {
        return Err("sentinel name belongs to a test namespace".to_owned());
    }
    let exists: bool =
        query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(&mut *owner)
            .await
            .map_err(|_| "check sentinel name failed".to_owned())?;
    if exists {
        return Err("sentinel name already exists".to_owned());
    }
    let statement = format!(
        "CREATE DATABASE {} TEMPLATE template0",
        quote_identifier(name)
    );
    query(statement.as_str())
        .execute(&mut *owner)
        .await
        .map_err(|_| "create sentinel database failed".to_owned())?;
    created.push(record_created(&mut *owner, name).await?);
    Ok(())
}

/// Connect directly to an auxiliary database using the owner credentials.
pub(super) async fn connect_database(
    config: &TemplateConfig,
    name: &str,
) -> Result<PgConnection, String> {
    let options = config
        .owner_options_for(name)
        .map_err(|error| error.to_string())?;
    PgConnection::connect_with(&options)
        .await
        .map_err(|_| "connect to auxiliary database failed".to_owned())
}

/// Assert one checked-out pool connection is on `expected` and `public`.
pub(super) async fn assert_connection_matches(
    connection: &mut PgConnection,
    expected: &str,
) -> Result<(), String> {
    let database: String = query_scalar("SELECT current_database()")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| "read current_database failed".to_owned())?;
    if database != expected {
        return Err("pool connection pointed at the wrong database".to_owned());
    }
    let schema: String = query_scalar("SELECT current_schema()")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| "read current_schema failed".to_owned())?;
    if schema != "public" {
        return Err("pool connection did not resolve to the public schema".to_owned());
    }
    Ok(())
}

/// Finalizer: drop only databases registered on a successful `CREATE`.
///
/// This deliberately does NOT run the broad namespace cleanup: that must only
/// ever run in the preflighted, deliberate scenario, never as a finalizer
/// that could delete a pre-existing database the moment a create failed or
/// registered nothing. With no records there are no targets and nothing is
/// deleted. A tracked name that collides with a configured owner/runtime source
/// is never dropped, and every tracked-cleanup failure is reported.
pub(super) async fn cleanup_owned(
    job: &TemplateConfig,
    created: &[CreatedDatabase],
) -> Result<(), String> {
    if created.is_empty() {
        return Ok(());
    }
    let mut errors = Vec::new();
    let sources = source_names(job);
    let (excluded, droppable): (Vec<_>, Vec<_>) = created
        .iter()
        .cloned()
        .partition(|object| sources.iter().any(|source| source == &object.name));
    for _ in &excluded {
        errors.push("refused to drop a tracked object that names a configured source".to_owned());
    }
    match job.owner_connection().await {
        Ok(mut owner) => {
            if let Err(error) = drop_tracked(&mut owner, &droppable).await {
                errors.push(format!("tracked cleanup: {error}"));
            }
        }
        Err(error) => errors.push(format!("cleanup connection: {error}")),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
