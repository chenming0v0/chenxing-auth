use crate::sqlx::Connection;
use crate::sqlx::migrate::{MigrateError, Migrator};

pub(super) async fn repair_oauth_client_description(
    connection: &mut crate::sqlx::PgConnection,
    migrator: &Migrator,
) -> Result<bool, MigrateError> {
    let expected = migrator.iter().find(|migration| migration.version == 47);
    let Some(expected) = expected else {
        return Ok(false);
    };

    let rows = crate::sqlx::query_as::<_, (i64, Vec<u8>, bool)>(
        "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *connection)
    .await?;
    let prefix = migrator
        .iter()
        .take_while(|migration| migration.version <= 46)
        .collect::<Vec<_>>();
    if !ledger_is_exact_prefix(&rows, &prefix) {
        return Ok(false);
    }

    let column_matches = crate::sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'oauth_clients'
              AND column_name = 'description'
              AND data_type = 'text'
              AND is_nullable = 'YES'
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    if !column_matches {
        return Ok(false);
    }

    let mut transaction = connection.begin().await?;
    crate::sqlx::query(
        r#"
        INSERT INTO _sqlx_migrations
            (version, description, success, checksum, execution_time)
        VALUES ($1, $2, TRUE, $3, 0)
        "#,
    )
    .bind(expected.version)
    .bind(expected.description.as_ref())
    .bind(expected.checksum.as_ref())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}

fn ledger_is_exact_prefix(
    rows: &[(i64, Vec<u8>, bool)],
    migrations: &[&crate::sqlx::migrate::Migration],
) -> bool {
    rows.len() == 46
        && migrations.len() == 46
        && rows.iter().zip(migrations).enumerate().all(
            |(index, ((version, checksum, success), migration))| {
                *success
                    && *version == (index + 1) as i64
                    && checksum.as_slice() == migration.checksum.as_ref()
            },
        )
}

#[cfg(test)]
mod tests {
    use super::ledger_is_exact_prefix;

    #[test]
    fn exact_prefix_requires_all_successful_checksums_and_rejects_a_tail() {
        use std::borrow::Cow;

        use crate::sqlx::migrate::{Migration, MigrationType};

        let migrations = (1..=46)
            .map(|version| {
                Migration::new(
                    version,
                    Cow::Owned(format!("migration {version}")),
                    MigrationType::Simple,
                    Cow::Owned("SELECT 1".to_owned()),
                    false,
                )
            })
            .collect::<Vec<_>>();
        let prefix = migrations.iter().collect::<Vec<_>>();
        let rows = migrations
            .iter()
            .map(|migration| (migration.version, migration.checksum.to_vec(), true))
            .collect::<Vec<_>>();

        assert!(ledger_is_exact_prefix(&rows, &prefix));
        assert!(!ledger_is_exact_prefix(&rows[..45], &prefix,));
        let mut dirty = rows.clone();
        dirty[45].2 = false;
        assert!(!ledger_is_exact_prefix(&dirty, &prefix));
    }
}
