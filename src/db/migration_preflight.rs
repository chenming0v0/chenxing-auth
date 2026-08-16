//! Checks that must pass before SQLx creates its metadata table or applies schema migrations.
//!
//! The published baseline qualifies pg_trgm operator classes through `public`. PostgreSQL's
//! `CREATE EXTENSION IF NOT EXISTS ... WITH SCHEMA public` does not relocate an extension that
//! already exists elsewhere, so accepting that state only defers failure until index creation.

use crate::sqlx::{PgConnection, migrate::MigrateError};

const PG_TRGM_EXTENSION: &str = "pg_trgm";
const REQUIRED_SCHEMA: &str = "public";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "pg_trgm is installed in schema {schema:?}, but this release's published migrations require \
     pg_trgm in schema public. No schema migration was executed. Changing search_path cannot \
     satisfy this contract. During a maintenance window, use a privileged PostgreSQL role to run \
     `ALTER EXTENSION pg_trgm SET SCHEMA public` after backup and dependency review, or migrate \
     into a fresh database where pg_trgm is absent; then rerun `chenxing-auth migrate`. Do not edit \
     published migration files or their checksums."
)]
struct PgTrgmSchemaMismatch {
    schema: String,
}

pub(super) async fn verify(connection: &mut PgConnection) -> Result<(), MigrateError> {
    let schema: Option<String> = crate::sqlx::query_scalar(
        "SELECT namespace.nspname
         FROM pg_catalog.pg_extension AS extension
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = extension.extnamespace
         WHERE extension.extname = $1",
    )
    .bind(PG_TRGM_EXTENSION)
    .fetch_optional(&mut *connection)
    .await?;

    validate_pg_trgm_schema(schema.as_deref())
        .map_err(|error| MigrateError::Execute(crate::sqlx::Error::Protocol(error.to_string())))
}

fn validate_pg_trgm_schema(schema: Option<&str>) -> Result<(), PgTrgmSchemaMismatch> {
    match schema {
        None | Some(REQUIRED_SCHEMA) => Ok(()),
        Some(schema) => Err(PgTrgmSchemaMismatch {
            schema: schema.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_pg_trgm_schema;

    #[test]
    fn absent_pg_trgm_is_allowed_for_the_baseline_to_create() {
        assert_eq!(validate_pg_trgm_schema(None), Ok(()));
    }

    #[test]
    fn pg_trgm_in_public_is_allowed() {
        assert_eq!(validate_pg_trgm_schema(Some("public")), Ok(()));
    }

    #[test]
    fn pg_trgm_outside_public_is_rejected_with_recovery_steps() {
        let error = validate_pg_trgm_schema(Some("extensions"))
            .expect_err("non-public pg_trgm must fail closed");
        let message = error.to_string();

        assert_eq!(error.schema, "extensions");
        for marker in [
            "require pg_trgm in schema public",
            "No schema migration was executed",
            "Changing search_path cannot satisfy this contract",
            "ALTER EXTENSION pg_trgm SET SCHEMA public",
            "fresh database where pg_trgm is absent",
            "Do not edit published migration files or their checksums",
        ] {
            assert!(
                message.contains(marker),
                "missing recovery marker: {marker}"
            );
        }
    }
}
