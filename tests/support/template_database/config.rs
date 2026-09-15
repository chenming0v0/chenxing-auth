//! Template database configuration: namespace, source URLs, and pure helpers.
//!
//! `TemplateConfig` deliberately does not implement `Debug`: it is derived from
//! connection URLs, and a derived debug dump is the easiest way to leak
//! credentials or options. Parsed `PgConnectOptions` values are never stored in
//! the struct either — they are parsed on demand and only used for connecting.

use std::str::FromStr;

use sqlx_postgres::PgConnectOptions;
use url::Url;

use super::error::DbTestError;
use super::names::{
    DATABASE_PREFIX_ENV, DatabaseName, Namespace, OWNER_DATABASE_URL_ENV, RUNTIME_DATABASE_URL_ENV,
    TEMPLATE_DATABASE_ENV,
};

/// Parsed, validated template database configuration.
pub struct TemplateConfig {
    namespace: Namespace,
    owner_url: String,
    source: DatabaseName,
}

impl TemplateConfig {
    /// Read the configuration from the required environment variables.
    ///
    /// Both `CHENXING_TEST_TEMPLATE_DATABASE` and `CHENXING_TEST_DATABASE_PREFIX`
    /// are required; there is no fallback when either is absent. The owner URL
    /// comes from `MIGRATION_DATABASE_URL` and the optional runtime URL from
    /// `DATABASE_URL` (parsed and protected, never used as a source fallback).
    pub fn from_env() -> Result<Self, DbTestError> {
        let template = read_required(TEMPLATE_DATABASE_ENV)?;
        let prefix = read_required(DATABASE_PREFIX_ENV)?;
        let owner_url = read_required(OWNER_DATABASE_URL_ENV)?;
        let runtime_url = read_optional(RUNTIME_DATABASE_URL_ENV);
        let namespace = Namespace::new(&template, &prefix)?;
        Self::from_values(namespace, &owner_url, runtime_url.as_deref())
    }

    /// Build a configuration from explicit values (pure; no environment access).
    pub fn from_values(
        namespace: Namespace,
        owner_url: &str,
        runtime_url: Option<&str>,
    ) -> Result<Self, DbTestError> {
        let source = parse_source_url(&namespace, owner_url)?;
        if let Some(runtime) = runtime_url {
            // The runtime database is parsed and validated so it can never be a
            // destructive target, but it is never used as a source fallback.
            let _ = parse_source_url(&namespace, runtime)?;
        }
        Ok(Self {
            namespace,
            owner_url: owner_url.to_owned(),
            source,
        })
    }

    /// The validated namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// The namespace template database name.
    pub fn template_name(&self) -> &DatabaseName {
        self.namespace.template_name()
    }

    /// Parse and validate any source URL against this namespace.
    pub fn validate_source_url(&self, url: &str) -> Result<DatabaseName, DbTestError> {
        parse_source_url(&self.namespace, url)
    }

    /// The owner (migration) source database parsed from `MIGRATION_DATABASE_URL`.
    pub(crate) fn source_name(&self) -> &DatabaseName {
        &self.source
    }

    /// Parse the owner URL and swap in `database`, preserving every other field.
    ///
    /// This is the only place a clone/template connection options value is
    /// built. The returned `PgConnectOptions` is never wrapped in a type that
    /// derives `Debug`.
    pub(crate) fn owner_options_for(
        &self,
        database: &str,
    ) -> Result<PgConnectOptions, DbTestError> {
        Ok(self.owner_options()?.database(database))
    }

    fn owner_options(&self) -> Result<PgConnectOptions, DbTestError> {
        url_selects_database(&self.owner_url)?;
        let options = PgConnectOptions::from_str(&self.owner_url)
            .map_err(|_| DbTestError::InvalidUrl(OWNER_DATABASE_URL_ENV))?;
        if options.get_database().is_none_or(str::is_empty) {
            return Err(DbTestError::InvalidUrl(
                "MIGRATION_DATABASE_URL must name a database",
            ));
        }
        Ok(options)
    }
}

/// Pure syntactic check that the URL text itself selects a database.
///
/// `PgConnectOptions::from_str` starts from `new_without_pgpass()`, which reads
/// `PGDATABASE`; without this check a URL with no selector would silently pick
/// up the ambient default. Only a non-empty URL path segment or a non-empty
/// `dbname` query parameter counts. The protected source name still comes from
/// SQLx's final parsed options, so a `dbname` query overriding the path is the
/// value validated against the namespace.
pub(crate) fn url_selects_database(url: &str) -> Result<(), DbTestError> {
    let parsed =
        Url::parse(url).map_err(|_| DbTestError::InvalidUrl("database URL is not parseable"))?;
    let path = parsed.path().trim_start_matches('/');
    let has_path = !path.is_empty();
    let has_query = parsed
        .query_pairs()
        .any(|(key, value)| key == "dbname" && !value.is_empty());
    if !has_path && !has_query {
        return Err(DbTestError::InvalidUrl(
            "database URL must select a database",
        ));
    }
    Ok(())
}

fn parse_source_url(namespace: &Namespace, url: &str) -> Result<DatabaseName, DbTestError> {
    url_selects_database(url)?;
    let options = PgConnectOptions::from_str(url)
        .map_err(|_| DbTestError::InvalidUrl("database URL is not parseable"))?;
    let database = options
        .get_database()
        .filter(|database| !database.is_empty())
        .ok_or(DbTestError::InvalidUrl(
            "database URL must name a database explicitly",
        ))?;
    namespace.validate_source_name(database)?;
    DatabaseName::new_validated(database)
}

fn read_required(name: &'static str) -> Result<String, DbTestError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(DbTestError::MissingEnv(name))
}

fn read_optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}
