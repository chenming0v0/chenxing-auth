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

fn classify_ledger(
    rows: &[(i64, Vec<u8>, bool)],
    expected: &[(i64, &[u8])],
) -> Result<(), SchemaStateError> {
    // A valid prefix means the database is simply waiting for the migration
    // command. Keep that distinct from a changed, reordered, or dirty ledger.
    let valid_prefix = rows.iter().zip(expected.iter()).all(
        |((version, checksum, success), (expected_version, expected_checksum))| {
            version == expected_version && *success && checksum.as_slice() == *expected_checksum
        },
    );
    if rows.len() < expected.len() && valid_prefix {
        return Err(SchemaStateError::Outdated {
            applied: rows.last().map(|(version, _, _)| *version).unwrap_or(0),
            required: expected.last().map(|(version, _)| *version).unwrap_or(0),
        });
    }
    if rows.len() != expected.len() || !valid_prefix {
        return Err(SchemaStateError::InconsistentLedger);
    }
    Ok(())
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

    let expected = expected
        .iter()
        .map(|migration| (migration.version, migration.checksum.as_ref()))
        .collect::<Vec<_>>();
    classify_ledger(&rows, &expected)
}

#[cfg(test)]
mod tests {
    use super::{SchemaStateError, classify_ledger};

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

    #[test]
    fn outdated_ledger_reports_applied_and_required_versions() {
        let error = SchemaStateError::Outdated {
            applied: 32,
            required: 45,
        };
        assert_eq!(
            error.to_string(),
            "database schema is at migration 32, but this release requires migration 45; run `chenxing-auth migrate` before starting the web service"
        );
    }

    #[test]
    fn valid_ledger_prefix_is_outdated_not_inconsistent() {
        let expected = &[(1, b"one".as_slice()), (2, b"two".as_slice())];
        let rows = vec![(1, b"one".to_vec(), true)];

        assert!(matches!(
            classify_ledger(&rows, expected),
            Err(SchemaStateError::Outdated {
                applied: 1,
                required: 2
            })
        ));
    }

    #[test]
    fn changed_checksum_remains_inconsistent() {
        let expected = &[(1, b"one".as_slice()), (2, b"two".as_slice())];
        let rows = vec![(1, b"changed".to_vec(), true), (2, b"two".to_vec(), true)];

        assert!(matches!(
            classify_ledger(&rows, expected),
            Err(SchemaStateError::InconsistentLedger)
        ));
    }
}
