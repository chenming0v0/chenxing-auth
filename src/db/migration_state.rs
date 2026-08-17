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
    #[error("database schema version could not be verified")]
    Database(#[from] crate::sqlx::Error),
}

fn require_current_version(applied: Option<i64>, required: i64) -> Result<(), SchemaStateError> {
    match applied {
        Some(applied) if applied == required => Ok(()),
        Some(applied) => Err(SchemaStateError::Outdated { applied, required }),
        None => Err(SchemaStateError::MissingLedger),
    }
}

pub async fn verify_schema_current(database: &super::Database) -> Result<(), SchemaStateError> {
    let required = super::embedded_migrator()
        .iter()
        .map(|migration| migration.version)
        .max()
        .expect("embedded migration history must not be empty");
    let applied = crate::sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(version) FILTER (WHERE success) FROM _sqlx_migrations",
    )
    .fetch_one(database)
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
    require_current_version(applied, required)
}

#[cfg(test)]
mod tests {
    use super::{SchemaStateError, require_current_version};

    const REQUIRED: i64 = 32;

    #[test]
    fn current_schema_version_is_accepted() {
        assert!(require_current_version(Some(REQUIRED), REQUIRED).is_ok());
    }

    #[test]
    fn stale_schema_version_is_rejected_with_the_required_version() {
        assert!(matches!(
            require_current_version(Some(27), REQUIRED),
            Err(SchemaStateError::Outdated {
                applied: 27,
                required: REQUIRED
            })
        ));
    }

    #[test]
    fn missing_migration_ledger_is_rejected() {
        assert!(matches!(
            require_current_version(None, REQUIRED),
            Err(SchemaStateError::MissingLedger)
        ));
    }
}
