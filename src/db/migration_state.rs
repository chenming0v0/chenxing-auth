#[derive(Debug, thiserror::Error)]
pub enum SchemaStateError {
    #[error(
        "database schema is not initialized; run `chenxing-auth migrate` before starting the web service"
    )]
    MissingLedger,
    #[error(
        "database schema is at migration {applied}, but this release requires migration {required}; run `chenxing-auth migrate` before starting the web service"
    )]
    Outdated { applied: i64, required: i64 },
    #[error("database schema migration ledger is inconsistent")]
    InconsistentLedger,
    #[error("database schema version could not be verified")]
    Database(#[from] crate::sqlx::Error),
}

pub async fn verify_schema_current(database: &super::Database) -> Result<(), SchemaStateError> {
    let migrations = super::embedded_migrator();
    let expected = migrations.iter().collect::<Vec<_>>();
    let rows = crate::sqlx::query_as::<_, (i64, Vec<u8>, bool)>(
        "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(database)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref()
            == Some("42P01")
        {
            SchemaStateError::MissingLedger
        } else {
            SchemaStateError::Database(error)
        }
    })?;

    if rows.len() != expected.len()
        || rows.iter().zip(expected.iter()).enumerate().any(
            |(index, ((version, checksum, success), migration))| {
                *version != migration.version
                    || !*success
                    || checksum.as_slice() != migration.checksum.as_ref()
                    || *version != (index + 1) as i64
            },
        )
    {
        return Err(SchemaStateError::InconsistentLedger);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SchemaStateError;

    #[test]
    fn inconsistent_ledger_is_a_distinct_startup_failure() {
        let error = SchemaStateError::InconsistentLedger;
        assert_eq!(
            error.to_string(),
            "database schema migration ledger is inconsistent"
        );
    }

    #[test]
    fn missing_ledger_remains_distinct_from_inconsistent_ledger() {
        assert!(matches!(
            SchemaStateError::MissingLedger,
            SchemaStateError::MissingLedger
        ));
        assert!(!matches!(
            SchemaStateError::MissingLedger,
            SchemaStateError::InconsistentLedger
        ));
    }
}
