use std::borrow::Cow;
use std::env;

use chenxing_auth::sqlx::migrate::{Migration, MigrationType, Migrator};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::sqlx::{Connection, PgConnection};
use uuid::Uuid;

fn normalize_migration_sql(sql: &'static str) -> Cow<'static, str> {
    if sql.contains('\r') {
        Cow::Owned(sql.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(sql)
    }
}

fn published_migrator() -> Migrator {
    let migrations: Vec<_> = [
        (
            1,
            "initial schema",
            include_str!("../../migrations/0001_initial.sql"),
        ),
        (2, "plans", include_str!("../../migrations/0002_plans.sql")),
        (
            3,
            "session outbox",
            include_str!("../../migrations/0003_session_outbox.sql"),
        ),
        (
            4,
            "relax deleted session outbox target",
            include_str!("../../migrations/0004_relax_deleted_session_outbox_target.sql"),
        ),
        (
            5,
            "session outbox event user",
            include_str!("../../migrations/0005_session_outbox_event_user.sql"),
        ),
        (
            6,
            "session epochs",
            include_str!("../../migrations/0006_session_epochs.sql"),
        ),
        (
            7,
            "plan default invariant",
            include_str!("../../migrations/0007_plan_default_invariant.sql"),
        ),
        (
            8,
            "admin query indexes",
            include_str!("../../migrations/0008_admin_query_indexes.sql"),
        ),
        (
            9,
            "system settings",
            include_str!("../../migrations/0009_system_settings.sql"),
        ),
        (
            10,
            "consent revoked at",
            include_str!("../../migrations/0010_consent_revoked_at.sql"),
        ),
        (
            11,
            "oauth provider pkce",
            include_str!("../../migrations/0011_oauth_provider_pkce.sql"),
        ),
        (
            12,
            "restore basic plan",
            include_str!("../../migrations/0012_restore_basic_plan.sql"),
        ),
        (
            13,
            "audit append only retention",
            include_str!("../../migrations/0013_audit_append_only_retention.sql"),
        ),
        (
            14,
            "session idle policy",
            include_str!("../../migrations/0014_session_idle_policy.sql"),
        ),
        (
            15,
            "admin search indexes",
            include_str!("../../migrations/0015_admin_search_indexes.sql"),
        ),
        (
            16,
            "client secret rotation version",
            include_str!("../../migrations/0016_client_secret_rotation_version.sql"),
        ),
        (
            17,
            "relax plan default policy",
            include_str!("../../migrations/0017_relax_plan_default_policy.sql"),
        ),
        (
            18,
            "seed security limits",
            include_str!("../../migrations/0018_seed_security_limits.sql"),
        ),
        (
            19,
            "audit runtime role",
            include_str!("../../migrations/0019_audit_runtime_role.sql"),
        ),
        (
            20,
            "user avatar",
            include_str!("../../migrations/0020_user_avatar.sql"),
        ),
        (
            21,
            "oauth provider require email verified claim",
            include_str!("../../migrations/0021_oauth_provider_require_email_verified_claim.sql"),
        ),
        (
            22,
            "session outbox retention",
            include_str!("../../migrations/0022_session_outbox_retention.sql"),
        ),
        (
            23,
            "consent state version",
            include_str!("../../migrations/0023_consent_state_version.sql"),
        ),
        (
            24,
            "runtime users sequence update",
            include_str!("../../migrations/0024_runtime_users_sequence_update.sql"),
        ),
        (
            25,
            "user canonical email",
            include_str!("../../migrations/0025_user_canonical_email.sql"),
        ),
        (
            26,
            "client secret refresh generation",
            include_str!("../../migrations/0026_client_secret_refresh_generation.sql"),
        ),
        (
            27,
            "repair canonical email constraint scope",
            include_str!("../../migrations/0027_repair_canonical_email_constraint_scope.sql"),
        ),
    ]
    .into_iter()
    .map(|(version, description, sql)| {
        Migration::new(
            version,
            Cow::Borrowed(description),
            MigrationType::Simple,
            normalize_migration_sql(sql),
            false,
        )
    })
    .collect();

    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

async fn revert_migrations_after_description(pool: &chenxing_auth::sqlx::PgPool) {
    for statement in [
        "DROP TABLE wallet_purchase_idempotency",
        "DROP TABLE user_quota_addon_purchases",
        "DROP TABLE plan_quota_addons",
        "ALTER TABLE users DROP COLUMN plan_entitlement_version",
        "DROP TABLE wallet_redemptions",
        "DROP TABLE wallet_redemption_codes",
        "DROP TABLE wallet_ledger",
        "DROP TABLE user_wallets",
        "ALTER TABLE plans DROP CONSTRAINT plans_billing_period_check, DROP CONSTRAINT plans_price_points_check, DROP COLUMN billing_period, DROP COLUMN price_points",
    ] {
        chenxing_auth::sqlx::query(statement)
            .execute(pool)
            .await
            .unwrap_or_else(|error| panic!("revert migrations after 0047 ({statement}): {error}"));
    }
}

#[tokio::test]
async fn published_database_upgrades_in_place_without_losing_identity_or_audit_data() {
    let database_url = env::var("MIGRATION_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let schema = format!("ctest_migration_upgrade_{}", Uuid::new_v4().simple());

    let mut bootstrap = PgConnection::connect(&database_url)
        .await
        .expect("connect migration owner");
    chenxing_auth::sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut bootstrap)
        .await
        .expect("create isolated migration schema");

    let schema_for_pool = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _meta| {
            let schema = schema_for_pool.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect isolated migration pool");

    published_migrator()
        .run(&pool)
        .await
        .expect("apply published migration snapshot");

    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users
             (username, email, canonical_email, password_hash, role, created_at, updated_at)
         VALUES ('upgrade-user', 'upgrade@example.com', 'upgrade@example.com',
                 'published-password-hash', 'owner', NOW(), NOW())
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed published user");
    let client_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_clients
              (client_id, client_name, redirect_uris, scopes, auth_method, owner_user_id, created_at)
          VALUES ('upgrade-client', 'Upgrade Client', '[\"https://client.example/callback\"]',
                  '[\"openid\"]', 'none', $1, NOW())
          RETURNING id",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("seed published client");
    let audit_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
             (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ('user', $1, 'migration.preserve', 'oauth_client', $2, '{}', NOW())
         RETURNING id",
    )
    .bind(user_id)
    .bind(client_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("seed published audit event");

    // v1.1.1 shipped the same final schema as a new destructive version-1
    // baseline. Recreate that exact published ledger fork without changing the
    // schema or seeded production data.
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations WHERE version > 1")
        .execute(&pool)
        .await
        .expect("remove historical ledger tail");
    chenxing_auth::sqlx::query(
        "UPDATE _sqlx_migrations \
         SET description = 'current schema baseline', \
             checksum = decode($1, 'hex') \
         WHERE version = 1",
    )
    .bind("ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95")
    .execute(&pool)
    .await
    .expect("install v1.1.1 flattened ledger");

    chenxing_auth::db::migrate(&pool)
        .await
        .expect("repair v1.1.1 ledger and upgrade through current migrations");

    let user: (String, String) =
        chenxing_auth::sqlx::query_as("SELECT username, canonical_email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("load upgraded user");
    assert_eq!(
        user,
        ("upgrade-user".to_owned(), "upgrade@example.com".to_owned())
    );

    let client: (String, i64) = chenxing_auth::sqlx::query_as(
        "SELECT client_id, owner_user_id FROM oauth_clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_one(&pool)
    .await
    .expect("load upgraded client");
    assert_eq!(client, ("upgrade-client".to_owned(), user_id));

    let audit: (String, String) =
        chenxing_auth::sqlx::query_as("SELECT action, resource_id FROM audit_events WHERE id = $1")
            .bind(audit_id)
            .fetch_one(&pool)
            .await
            .expect("load upgraded audit event");
    assert_eq!(
        audit,
        ("migration.preserve".to_owned(), client_id.to_string())
    );

    let applied: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read upgraded migration history");
    // 0030/0031 来自 #50-479 批次合并；0032 修复运行时 migration ledger 权限。
    // 0033–0051 是后续追加的邀请码、邮箱变更、outbox fence、archive INSERT
    // 回收、access-token 撤销、JSONB shape CHECK、签发时 idle 窗口、
    // auth_method 与 secret 哈希配对 CHECK、client 展示字段、钱包与套餐定价、
    // 兑换码、配额加购和钱包购买幂等。
    assert_eq!(applied, (1_i64..=51).collect::<Vec<_>>());

    // A v1.1.16 database may already have the 0047 schema change while its
    // ledger stops at 0046. The compatibility repair must record 0047 from
    // the embedded migration metadata before SQLx runs the remaining tail.
    revert_migrations_after_description(&pool).await;
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations WHERE version >= 47")
        .execute(&pool)
        .await
        .expect("remove version-47 ledger tail");
    chenxing_auth::db::migrate(&pool)
        .await
        .expect("repair existing description column and continue migration");
    let repaired_description: (String, Vec<u8>) = chenxing_auth::sqlx::query_as(
        "SELECT description, checksum FROM _sqlx_migrations WHERE version = 47",
    )
    .fetch_one(&pool)
    .await
    .expect("read repaired version-47 ledger row");
    let checksum_before_repeat = repaired_description.1.clone();
    assert_eq!(repaired_description.0, "oauth client description");

    chenxing_auth::db::migrate(&pool)
        .await
        .expect("healthy version-47 ledger remains migratable");
    let checksum_after_repeat: Vec<u8> = chenxing_auth::sqlx::query_scalar(
        "SELECT checksum FROM _sqlx_migrations WHERE version = 47",
    )
    .fetch_one(&pool)
    .await
    .expect("read stable version-47 checksum");
    assert_eq!(checksum_after_repeat, checksum_before_repeat);

    // With the column absent, the original 0047 SQL must remain responsible
    // for creating it; the compatibility path must not invent the schema.
    let later_ledger: Vec<(i64, String, Vec<u8>, bool, i64)> = chenxing_auth::sqlx::query_as(
        "SELECT version, description, checksum, success, execution_time
         FROM _sqlx_migrations WHERE version >= 48 ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("save later migration ledger rows");
    revert_migrations_after_description(&pool).await;
    chenxing_auth::sqlx::query("ALTER TABLE oauth_clients DROP COLUMN description")
        .execute(&pool)
        .await
        .expect("remove description column for original migration test");
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations WHERE version >= 47")
        .execute(&pool)
        .await
        .expect("remove version-47 ledger for original migration test");
    chenxing_auth::db::migrate(&pool)
        .await
        .expect("original version-47 migration creates missing column");
    let description_exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = current_schema()
                          AND table_name = 'oauth_clients'
                          AND column_name = 'description')",
    )
    .fetch_one(&pool)
    .await
    .expect("check description column after original migration");
    assert!(description_exists);

    // A missing 0047 row with a later row is not a recognized prefix and must
    // not be rewritten. Leave the schema intact so normal SQLx validation
    // fails closed on the inconsistent ledger.
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations WHERE version >= 47")
        .execute(&pool)
        .await
        .expect("remove version-47 ledger before tail guard test");
    let later = later_ledger
        .first()
        .expect("current migrations include version 48");
    chenxing_auth::sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version, description, checksum, success, execution_time)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(later.0)
    .bind(&later.1)
    .bind(&later.2)
    .bind(later.3)
    .bind(later.4)
    .execute(&pool)
    .await
    .expect("install synthetic later ledger row");
    let result = chenxing_auth::db::migrate(&pool).await;
    assert!(result.is_err(), "later ledger rows must reject migration");
    let ledger_versions: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version >= 47 ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read ledger after tail guard");
    assert_eq!(ledger_versions, vec![48]);
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 48")
        .execute(&pool)
        .await
        .expect("remove synthetic later ledger row");

    // A database initialized by v1.1.2 has the same schema but records the
    // flattened baseline plus the two then-current migrations as versions 1-3.
    // The compatibility path must recognize and repair that exact ledger too.
    //
    // 真实 v1.1.2 库的 schema 止于 29 号终态；上一段升级已经把 0030 之后的
    // 步骤应用进来，先把这些 schema 变更回退，模拟才忠实。列/表均为空，
    // 回退不影响被保留的身份数据。
    for statement in [
        "DROP TABLE wallet_purchase_idempotency",
        "DROP TABLE user_quota_addon_purchases",
        "DROP TABLE plan_quota_addons",
        "ALTER TABLE users DROP COLUMN plan_entitlement_version",
        "DROP TABLE wallet_redemptions",
        "DROP TABLE wallet_redemption_codes",
        "DROP TABLE wallet_ledger",
        "DROP TABLE user_wallets",
        "ALTER TABLE plans DROP CONSTRAINT plans_billing_period_check, DROP CONSTRAINT plans_price_points_check, DROP COLUMN billing_period, DROP COLUMN price_points",
        "ALTER TABLE oauth_clients DROP COLUMN description, DROP COLUMN logo_uri, DROP COLUMN client_uri",
        "ALTER TABLE user_passkeys DROP COLUMN state_version",
        "DROP TABLE client_operation_idempotency",
        "DROP TABLE registration_invitation_uses",
        "DROP TABLE registration_invitation_codes",
        "DROP TABLE email_outbox",
        "DROP TABLE user_email_change_challenges",
        "ALTER TABLE session_outbox DROP COLUMN claim_generation, DROP COLUMN claim_token",
        "DROP TABLE revoked_access_tokens",
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_redirect_uris_check, DROP CONSTRAINT oauth_clients_scopes_check",
        "ALTER TABLE user_consents DROP CONSTRAINT user_consents_scopes_check",
        "ALTER TABLE oauth_providers DROP CONSTRAINT oauth_providers_scopes_check",
        "ALTER TABLE user_passkeys DROP CONSTRAINT user_passkeys_credential_check",
        "ALTER TABLE user_sessions DROP COLUMN idle_timeout_seconds",
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_auth_method_secret_check",
    ] {
        chenxing_auth::sqlx::query(statement)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("revert post-v1.1.2 schema ({statement}): {error}"));
    }
    chenxing_auth::sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("clear canonical ledger before v1.1.2 simulation");
    for (version, description, checksum) in [
        (
            1_i64,
            "current schema baseline",
            "ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95",
        ),
        (
            2_i64,
            "controlled runtime issuer",
            "70b7c2bd57303895720d0e13fbc56b16d43645f67363803fac73411fd8e4526f",
        ),
        (
            3_i64,
            "bounded plan quotas",
            "56e9d9ea680ac129115cc21ac2ff5029f9f2746683bdb9cf42ad966afb3571c4",
        ),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO _sqlx_migrations \
                 (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, decode($3, 'hex'), 0)",
        )
        .bind(version)
        .bind(description)
        .bind(checksum)
        .execute(&pool)
        .await
        .expect("install v1.1.2 flattened ledger row");
    }

    chenxing_auth::db::migrate(&pool)
        .await
        .expect("repair v1.1.2 flattened ledger");
    let repaired: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read repaired v1.1.2 migration history");
    assert_eq!(repaired, (1_i64..=51).collect::<Vec<_>>());

    let preserved: (i64, i64, i64) = chenxing_auth::sqlx::query_as(
        "SELECT \
             (SELECT COUNT(*) FROM users WHERE id = $1), \
             (SELECT COUNT(*) FROM oauth_clients WHERE id = $2), \
             (SELECT COUNT(*) FROM audit_events WHERE id = $3)",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(audit_id)
    .fetch_one(&pool)
    .await
    .expect("verify data after v1.1.2 ledger repair");
    assert_eq!(preserved, (1, 1, 1));

    pool.close().await;
    chenxing_auth::sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut bootstrap)
        .await
        .expect("drop isolated migration schema");
}

#[tokio::test]
async fn flattened_repair_rejects_trigger_names_from_other_schema_or_wrong_table() {
    let database_url = env::var("MIGRATION_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let suffix = Uuid::new_v4().simple().to_string();
    let target_schema = format!("ctest_trigger_target_{suffix}");
    let decoy_schema = format!("ctest_trigger_decoy_{suffix}");
    let mut bootstrap = PgConnection::connect(&database_url)
        .await
        .expect("connect migration owner");
    chenxing_auth::sqlx::query(&format!("CREATE SCHEMA {target_schema}"))
        .execute(&mut bootstrap)
        .await
        .expect("create trigger isolation schemas");
    chenxing_auth::sqlx::query(&format!("CREATE SCHEMA {decoy_schema}"))
        .execute(&mut bootstrap)
        .await
        .expect("create trigger decoy schema");

    let target_for_pool = target_schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _meta| {
            let schema = target_for_pool.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect trigger target pool");
    chenxing_auth::db::migrate(&pool)
        .await
        .expect("initialize current target schema");

    for statement in [
        "DROP TABLE wallet_purchase_idempotency",
        "DROP TABLE user_quota_addon_purchases",
        "DROP TABLE plan_quota_addons",
        "ALTER TABLE users DROP COLUMN plan_entitlement_version",
        "DROP TABLE wallet_redemptions",
        "DROP TABLE wallet_redemption_codes",
        "DROP TABLE wallet_ledger",
        "DROP TABLE user_wallets",
        "ALTER TABLE plans DROP CONSTRAINT plans_billing_period_check, DROP CONSTRAINT plans_price_points_check, DROP COLUMN billing_period, DROP COLUMN price_points",
        "ALTER TABLE oauth_clients DROP COLUMN description, DROP COLUMN logo_uri, DROP COLUMN client_uri",
        "ALTER TABLE user_passkeys DROP COLUMN state_version",
        "DROP TABLE client_operation_idempotency",
        "DROP TABLE registration_invitation_uses",
        "DROP TABLE registration_invitation_codes",
        "DROP TABLE email_outbox",
        "DROP TABLE user_email_change_challenges",
        "ALTER TABLE session_outbox DROP COLUMN claim_generation, DROP COLUMN claim_token",
        "DROP TABLE revoked_access_tokens",
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_redirect_uris_check, DROP CONSTRAINT oauth_clients_scopes_check",
        "ALTER TABLE user_consents DROP CONSTRAINT user_consents_scopes_check",
        "ALTER TABLE oauth_providers DROP CONSTRAINT oauth_providers_scopes_check",
        "ALTER TABLE user_passkeys DROP CONSTRAINT user_passkeys_credential_check",
        "ALTER TABLE user_sessions DROP COLUMN idle_timeout_seconds",
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_auth_method_secret_check",
        "DROP TRIGGER audit_events_append_only_trigger ON audit_events",
        "CREATE TABLE trigger_decoy_target (id BIGINT)",
        "CREATE FUNCTION trigger_decoy_function() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "CREATE TRIGGER audit_events_append_only_trigger
         BEFORE INSERT ON trigger_decoy_target
         FOR EACH ROW EXECUTE FUNCTION trigger_decoy_function()",
        "DELETE FROM _sqlx_migrations",
    ] {
        chenxing_auth::sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("prepare flattened target with wrong-table trigger");
    }
    for (version, description, checksum) in [
        (
            1_i64,
            "current schema baseline",
            "ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95",
        ),
        (
            2_i64,
            "controlled runtime issuer",
            "70b7c2bd57303895720d0e13fbc56b16d43645f67363803fac73411fd8e4526f",
        ),
        (
            3_i64,
            "bounded plan quotas",
            "56e9d9ea680ac129115cc21ac2ff5029f9f2746683bdb9cf42ad966afb3571c4",
        ),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO _sqlx_migrations
                 (version, description, success, checksum, execution_time)
             VALUES ($1, $2, TRUE, decode($3, 'hex'), 0)",
        )
        .bind(version)
        .bind(description)
        .bind(checksum)
        .execute(&pool)
        .await
        .expect("install flattened ledger row");
    }
    for statement in [
        format!("CREATE TABLE {decoy_schema}.audit_events (id BIGINT)"),
        format!(
            "CREATE FUNCTION {decoy_schema}.reject_audit_event_mutation() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
        ),
        format!(
            "CREATE TRIGGER audit_events_append_only_trigger
             BEFORE INSERT ON {decoy_schema}.audit_events
             FOR EACH ROW EXECUTE FUNCTION {decoy_schema}.reject_audit_event_mutation()"
        ),
    ] {
        chenxing_auth::sqlx::query(&statement)
            .execute(&mut bootstrap)
            .await
            .expect("create cross-schema trigger decoy");
    }

    let migration_result = chenxing_auth::db::migrate(&pool).await;
    let ledger: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read ledger after rejected repair");
    pool.close().await;
    chenxing_auth::sqlx::query(&format!("DROP SCHEMA {target_schema} CASCADE"))
        .execute(&mut bootstrap)
        .await
        .expect("drop trigger target schema");
    chenxing_auth::sqlx::query(&format!("DROP SCHEMA {decoy_schema} CASCADE"))
        .execute(&mut bootstrap)
        .await
        .expect("drop trigger decoy schema");

    let error = migration_result
        .expect_err("wrong-table and cross-schema trigger names must not satisfy flattened repair");
    assert!(
        error.to_string().contains("does not match that release"),
        "unexpected migration error: {error}"
    );
    assert_eq!(
        ledger,
        vec![1, 2, 3],
        "failed repair must not rewrite the ledger"
    );
}
