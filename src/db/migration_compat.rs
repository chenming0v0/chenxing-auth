use crate::sqlx::Connection;
use crate::sqlx::migrate::{Migrate, MigrateError, Migrator};

use super::{Database, migration_preflight, roles};

const FLATTENED_BASELINE_CHECKSUM: &str =
    "ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95";
const FLATTENED_ISSUER_CHECKSUM: &str =
    "70b7c2bd57303895720d0e13fbc56b16d43645f67363803fac73411fd8e4526f";
const FLATTENED_QUOTA_CHECKSUM: &str =
    "56e9d9ea680ac129115cc21ac2ff5029f9f2746683bdb9cf42ad966afb3571c4";

#[derive(Debug, PartialEq, Eq)]
struct LedgerRow {
    version: i64,
    checksum: String,
    success: bool,
}

pub(super) async fn run(database: &Database, mut migrator: Migrator) -> Result<(), MigrateError> {
    let mut connection = database.acquire().await?;
    Migrate::lock(&mut *connection).await?;

    let result = async {
        // The pg_trgm placement check, role provisioning, flattened-ledger repair,
        // and normal SQLx migration run share one database-scoped migration lock.
        // This closes both the preflight check/use race and the compatibility
        // ledger rewrite window (#480, #490).
        migration_preflight::verify(&mut connection).await?;
        roles::ensure_runtime_role(&mut *connection).await?;
        Migrate::ensure_migrations_table(&mut *connection).await?;
        if let Some(version) = Migrate::dirty_version(&mut *connection).await? {
            return Err(MigrateError::Dirty(version));
        }

        if let Some(target_version) = repair_flattened_ledger(&mut connection, &migrator).await? {
            tracing::warn!(
                target_version,
                "repaired a recognized flattened SQLx migration ledger after schema verification"
            );
        }

        // The compatibility repair and normal migration run share SQLx's PostgreSQL
        // advisory lock, so no second process can observe the temporary ledger rewrite.
        migrator.set_locking(false);
        migrator.run_direct(&mut *connection).await
    }
    .await;

    let unlock_result = Migrate::unlock(&mut *connection).await;
    if unlock_result.is_err() {
        connection.close_on_drop();
    }

    match result {
        Err(error) => Err(error),
        Ok(()) => unlock_result,
    }
}

async fn repair_flattened_ledger(
    connection: &mut crate::sqlx::PgConnection,
    migrator: &Migrator,
) -> Result<Option<i64>, MigrateError> {
    let rows = crate::sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT version, encode(checksum, 'hex'), success \
         FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|(version, checksum, success)| LedgerRow {
        version,
        checksum,
        success,
    })
    .collect::<Vec<_>>();

    if rows.first().map(|row| row.checksum.as_str()) != Some(FLATTENED_BASELINE_CHECKSUM) {
        return Ok(None);
    }

    let target_version = flattened_target_version(&rows).ok_or_else(|| {
        compatibility_error(
            "recognized the published flattened migration baseline, but the remaining \
             _sqlx_migrations rows do not match a supported v1.1.1/v1.1.2 ledger; \
             refusing to rewrite migration history",
        )
    })?;

    verify_flattened_schema(connection, target_version).await?;

    let expected = migrator
        .iter()
        .filter(|migration| migration.version <= target_version)
        .collect::<Vec<_>>();
    if expected.len() != target_version as usize
        || expected
            .iter()
            .enumerate()
            .any(|(index, migration)| migration.version != (index + 1) as i64)
    {
        return Err(compatibility_error(
            "embedded migration history is not contiguous; refusing flattened ledger repair",
        ));
    }

    let mut transaction = connection.begin().await?;
    crate::sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&mut *transaction)
        .await?;

    for migration in expected {
        crate::sqlx::query(
            "INSERT INTO _sqlx_migrations \
                 (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, $3, 0)",
        )
        .bind(migration.version)
        .bind(migration.description.as_ref())
        .bind(migration.checksum.as_ref())
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(Some(target_version))
}

fn flattened_target_version(rows: &[LedgerRow]) -> Option<i64> {
    const V1_1_1: &[(i64, &str)] = &[(1, FLATTENED_BASELINE_CHECKSUM)];
    const V1_1_2_ISSUER_ONLY: &[(i64, &str)] = &[
        (1, FLATTENED_BASELINE_CHECKSUM),
        (2, FLATTENED_ISSUER_CHECKSUM),
    ];
    const V1_1_2: &[(i64, &str)] = &[
        (1, FLATTENED_BASELINE_CHECKSUM),
        (2, FLATTENED_ISSUER_CHECKSUM),
        (3, FLATTENED_QUOTA_CHECKSUM),
    ];

    if ledger_matches(rows, V1_1_1) {
        Some(27)
    } else if ledger_matches(rows, V1_1_2_ISSUER_ONLY) {
        Some(28)
    } else if ledger_matches(rows, V1_1_2) {
        Some(29)
    } else {
        None
    }
}

fn ledger_matches(rows: &[LedgerRow], expected: &[(i64, &str)]) -> bool {
    rows.len() == expected.len()
        && rows.iter().zip(expected).all(|(row, expected)| {
            row.success && row.version == expected.0 && row.checksum == expected.1
        })
}

async fn verify_flattened_schema(
    connection: &mut crate::sqlx::PgConnection,
    target_version: i64,
) -> Result<(), MigrateError> {
    let valid = crate::sqlx::query_scalar::<_, bool>(
        r#"
        SELECT
            NOT EXISTS (
                SELECT 1
                FROM (VALUES
                    ('plans'), ('users'), ('oauth_clients'), ('user_consents'),
                    ('user_sessions'), ('user_totp_factors'), ('user_passkeys'),
                    ('oauth_providers'), ('oauth_external_identities'), ('audit_events'),
                    ('app_settings'), ('session_outbox'), ('audit_events_archive')
                ) AS required(table_name)
                WHERE to_regclass(format('%I.%I', current_schema(), required.table_name)) IS NULL
            )
            AND NOT EXISTS (
                SELECT 1
                FROM (VALUES
                    ('plans', 'oauth_clients_limit'), ('plans', 'daily_auth_limit'),
                    ('plans', 'monthly_auth_limit'), ('plans', 'max_qps'),
                    ('users', 'canonical_email'), ('users', 'plan_id'),
                    ('users', 'plan_expires_at'), ('users', 'session_epoch'),
                    ('users', 'avatar_data'), ('users', 'avatar_mime'),
                    ('users', 'avatar_updated_at'),
                    ('oauth_clients', 'client_secret_version'),
                    ('oauth_clients', 'allow_legacy_refresh_tokens'),
                    ('user_consents', 'revoked_at'), ('user_consents', 'state_version'),
                    ('user_sessions', 'session_payload'),
                    ('user_sessions', 'session_epoch'), ('user_sessions', 'last_seen_at'),
                    ('oauth_providers', 'pkce_enabled'),
                    ('oauth_providers', 'email_verified_claim'),
                    ('session_outbox', 'user_id'), ('session_outbox', 'generation'),
                    ('session_outbox', 'dead_lettered_at')
                ) AS required(table_name, column_name)
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns AS columns
                    WHERE columns.table_schema = current_schema()
                      AND columns.table_name = required.table_name
                      AND columns.column_name = required.column_name
                )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM (VALUES
                    ('plans_single_default_idx'), ('users_canonical_email_key'),
                    ('user_sessions_active_created_idx'),
                    ('session_outbox_dead_letter_idx')
                ) AS required(object_name)
                WHERE to_regclass(format('%I.%I', current_schema(), required.object_name)) IS NULL
            )
            AND to_regprocedure(
                    format('%I.archive_audit_events(integer,integer)', current_schema())
                ) IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM (VALUES
                    (
                        'audit_events_append_only_trigger',
                        'audit_events',
                        'reject_audit_event_mutation',
                        58
                    ),
                    (
                        'audit_events_archive_append_only_trigger',
                        'audit_events_archive',
                        'reject_audit_event_mutation',
                        58
                    )
                ) AS required(trigger_name, table_name, function_name, trigger_type)
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger AS trigger_row
                    JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
                    JOIN pg_namespace AS relation_namespace
                      ON relation_namespace.oid = relation.relnamespace
                    JOIN pg_proc AS routine ON routine.oid = trigger_row.tgfoid
                    JOIN pg_namespace AS routine_namespace
                      ON routine_namespace.oid = routine.pronamespace
                    WHERE trigger_row.tgname = required.trigger_name
                      AND NOT trigger_row.tgisinternal
                      AND trigger_row.tgenabled = 'O'
                      AND trigger_row.tgtype = required.trigger_type::smallint
                      AND trigger_row.tgnargs = 0
                      AND relation_namespace.nspname = current_schema()
                      AND relation.relname = required.table_name
                      AND relation.relkind IN ('r', 'p')
                      AND routine_namespace.nspname = current_schema()
                      AND routine.proname = required.function_name
                      AND routine.pronargs = 0
                      AND routine.prorettype = 'trigger'::regtype
                )
            )
            AND (
                $1 < 28
                OR (
                    EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = current_schema()
                          AND table_name = 'app_settings'
                          AND column_name = 'generation'
                    )
                    AND to_regprocedure(
                            format('%I.set_app_issuer(text,bigint)', current_schema())
                        ) IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                        FROM pg_trigger AS trigger_row
                        JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
                        JOIN pg_namespace AS relation_namespace
                          ON relation_namespace.oid = relation.relnamespace
                        JOIN pg_proc AS routine ON routine.oid = trigger_row.tgfoid
                        JOIN pg_namespace AS routine_namespace
                          ON routine_namespace.oid = routine.pronamespace
                        WHERE trigger_row.tgname = 'app_issuer_controlled_write_trigger'
                          AND NOT trigger_row.tgisinternal
                          AND trigger_row.tgenabled = 'O'
                          AND trigger_row.tgtype = 31
                          AND trigger_row.tgnargs = 0
                          AND relation_namespace.nspname = current_schema()
                          AND relation.relname = 'app_settings'
                          AND relation.relkind IN ('r', 'p')
                          AND routine_namespace.nspname = current_schema()
                          AND routine.proname = 'guard_app_issuer_mutation'
                          AND routine.pronargs = 0
                          AND routine.prorettype = 'trigger'::regtype
                    )
                )
            )
            AND (
                $1 < 46
                OR NOT EXISTS (
                    SELECT 1
                    FROM (VALUES
                        ('oauth_clients', 'logo_uri'),
                        ('oauth_clients', 'client_uri')
                    ) AS required(table_name, column_name)
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM information_schema.columns AS columns
                        WHERE columns.table_schema = current_schema()
                          AND columns.table_name = required.table_name
                          AND columns.column_name = required.column_name
                    )
                )
            )
            AND (
                $1 < 29
                OR NOT EXISTS (
                    SELECT 1
                    FROM (VALUES
                        ('plans_daily_auth_limit_check'),
                        ('plans_monthly_auth_limit_check'),
                        ('plans_max_qps_check')
                    ) AS required(constraint_name)
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint AS constraints
                        JOIN pg_class AS relation ON relation.oid = constraints.conrelid
                        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                        WHERE namespace.nspname = current_schema()
                          AND relation.relname = 'plans'
                          AND constraints.conname = required.constraint_name
                    )
                )
            )
        "#,
    )
    .bind(target_version)
    .fetch_one(&mut *connection)
    .await?;

    if valid {
        Ok(())
    } else {
        Err(compatibility_error(
            "published flattened migration checksums were recognized, but the database schema \
             does not match that release; refusing automatic ledger repair",
        ))
    }
}

fn compatibility_error(message: &str) -> MigrateError {
    crate::sqlx::Error::Protocol(message.to_owned()).into()
}

#[cfg(test)]
mod tests {
    use super::{
        FLATTENED_BASELINE_CHECKSUM, FLATTENED_ISSUER_CHECKSUM, FLATTENED_QUOTA_CHECKSUM,
        LedgerRow, flattened_target_version,
    };

    fn row(version: i64, checksum: &str) -> LedgerRow {
        LedgerRow {
            version,
            checksum: checksum.to_owned(),
            success: true,
        }
    }

    #[test]
    fn recognizes_every_published_flattened_ledger_shape() {
        assert_eq!(
            flattened_target_version(&[row(1, FLATTENED_BASELINE_CHECKSUM)]),
            Some(27)
        );
        assert_eq!(
            flattened_target_version(&[
                row(1, FLATTENED_BASELINE_CHECKSUM),
                row(2, FLATTENED_ISSUER_CHECKSUM),
            ]),
            Some(28)
        );
        assert_eq!(
            flattened_target_version(&[
                row(1, FLATTENED_BASELINE_CHECKSUM),
                row(2, FLATTENED_ISSUER_CHECKSUM),
                row(3, FLATTENED_QUOTA_CHECKSUM),
            ]),
            Some(29)
        );
    }

    #[test]
    fn rejects_dirty_or_unknown_flattened_ledgers() {
        let mut dirty = row(1, FLATTENED_BASELINE_CHECKSUM);
        dirty.success = false;
        assert_eq!(flattened_target_version(&[dirty]), None);
        assert_eq!(
            flattened_target_version(&[row(1, FLATTENED_BASELINE_CHECKSUM), row(2, "unknown"),]),
            None
        );
    }
}
