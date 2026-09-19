use super::{
    CI_WORKFLOW, DATABASE_BASELINE, DB_MIGRATION_COMPAT_DESCRIPTION_MODULE,
    DB_MIGRATION_COMPAT_MODULE, DB_MIGRATION_PREFLIGHT_MODULE, DB_MODULE, DB_ROLES_MODULE,
    PUBLISHED_MIGRATION_CHECKSUMS,
};

/// Sorted `*.sql` filenames in the repository's `migrations` directory.
///
/// This is the independent source of truth for how many migrations exist and
/// what they are named; tests compare the embedded registrations against it
/// instead of re-pinning a hard-coded total.
fn migration_file_names() -> Vec<String> {
    let mut names = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn database_uses_forward_only_transactional_migration_history() {
    assert!(DB_MODULE.contains("Versions 1-27 have shipped and their SQL bytes are immutable"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0001_initial.sql\")"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0029_plan_quota_bounds.sql\")"));
    // 0030/0031（passkey state version、client operation idempotency）来自
    // #50-479 批次的合并；0032 收紧 SQLx migration ledger 的运行时权限。
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0030_passkey_state_version.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0031_client_operation_idempotency.sql\")")
    );
    assert!(
        DB_MODULE.contains(
            "include_str!(\"../../migrations/0032_runtime_migration_ledger_boundary.sql\")"
        )
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0033_registration_invitation_codes.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0034_user_email_change_challenges.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0035_session_outbox_claim_fence.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0036_revoke_runtime_archive_insert.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0037_revoked_access_tokens.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0038_jsonb_oauth_consent_shapes.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0039_session_issued_idle_timeout.sql\")")
    );
    assert!(
        DB_MODULE.contains(
            "include_str!(\"../../migrations/0040_oauth_client_auth_method_secret.sql\")"
        )
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0041_email_change_attempt_budget.sql\")")
    );
    assert!(
        DB_MODULE.contains(
            "include_str!(\"../../migrations/0042_email_change_attempt_budget_fix.sql\")"
        )
    );
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0043_email_outbox.sql\")"));
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0044_oauth_provider_state_version.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0045_email_security_alert_outbox.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0046_oauth_client_presentation.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0047_oauth_client_description.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0048_wallet_and_plan_pricing.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0049_wallet_redemption_codes.sql\")")
    );
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0050_quota_addons.sql\")"));
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0051_wallet_purchase_idempotency.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0052_external_identity_snapshots.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0053_cltermux_linked_accounts.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0054_account_provider_registry.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0055_client_numeric_app_id.sql\")")
    );
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0056_client_owner_backfill.sql\")")
    );
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0057_client_quota_exempt.sql\")"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0058_account_portal.sql\")"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0059_resource_services.sql\")"));

    // The migrations directory is the independent source of truth for the
    // current history. Every on-disk SQL file must be embedded exactly once in
    // src/db/mod.rs, and the embedded set must not contain anything the
    // directory lacks, so registration can never silently drift from the
    // directory and no migration total needs to be re-pinned here.
    let migration_files = migration_file_names();
    assert!(
        !migration_files.is_empty(),
        "the forward-only history must contain at least one migration"
    );
    for file_name in &migration_files {
        let registration = format!("include_str!(\"../../migrations/{file_name}\")");
        assert!(
            DB_MODULE.contains(registration.as_str()),
            "embedded migrator is missing registration for {file_name}"
        );
    }
    assert_eq!(
        DB_MODULE
            .matches("include_str!(\"../../migrations/")
            .count(),
        migration_files.len(),
        "embedded migration registrations must match the migrations directory exactly"
    );
    assert!(
        DB_MODULE.contains("normalize_migration_sql(sql)")
            && DB_MODULE.contains("MigrationType::Simple"),
        "the schema migrations must remain transactional"
    );

    let run_migrations = DB_MODULE
        .find("migration_compat::run(database, embedded_migrator()).await?;")
        .expect("schema migrations must run");
    let preflight = DB_MIGRATION_COMPAT_MODULE
        .find("migration_preflight::verify(&mut connection).await?;")
        .expect("pg_trgm placement must be checked inside the migration lock");
    let ensure_role = DB_MIGRATION_COMPAT_MODULE
        .find("roles::ensure_runtime_role(&mut *connection).await?;")
        .expect("runtime role must be provisioned inside the migration lock");
    let ensure_ledger = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::ensure_migrations_table(&mut *connection).await?;")
        .expect("migration ledger must be initialized after preflight");
    assert!(run_migrations > 0);
    assert!(preflight < ensure_role && ensure_role < ensure_ledger);
    for checksum in [
        "ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95",
        "70b7c2bd57303895720d0e13fbc56b16d43645f67363803fac73411fd8e4526f",
        "56e9d9ea680ac129115cc21ac2ff5029f9f2746683bdb9cf42ad966afb3571c4",
    ] {
        assert!(
            DB_MIGRATION_COMPAT_MODULE.contains(checksum),
            "flattened published checksum must remain explicitly recognized"
        );
    }
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("verify_flattened_schema"));
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("repair_oauth_client_description"));
    assert!(DB_MIGRATION_COMPAT_DESCRIPTION_MODULE.contains("ledger_is_exact_prefix"));
    assert!(DB_MIGRATION_COMPAT_DESCRIPTION_MODULE.contains("information_schema.columns"));
    assert!(DB_MIGRATION_COMPAT_DESCRIPTION_MODULE.contains("data_type = 'text'"));
    assert!(DB_MIGRATION_COMPAT_DESCRIPTION_MODULE.contains("is_nullable = 'YES'"));
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("Migrate::lock"));
    assert!(DB_ROLES_MODULE.contains("CREATE ROLE chenxing_runtime LOGIN"));
    assert!(!DATABASE_BASELINE.contains("CREATE ROLE"));

    assert_eq!(
        migration_files.first().map(String::as_str),
        Some("0001_initial.sql"),
        "the forward-only history must start at the initial schema"
    );
    let versions = migration_files
        .iter()
        .map(|file_name| {
            file_name[..4]
                .parse::<u32>()
                .expect("migration filename starts with a version prefix")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        versions,
        (1..=u32::try_from(migration_files.len()).expect("migration count fits in u32"))
            .collect::<Vec<_>>(),
        "migration versions must be contiguous and forward-only"
    );

    assert_eq!(
        DATABASE_BASELINE.matches("CREATE TABLE ").count(),
        10,
        "the published version-1 migration must remain the original ten-table schema"
    );
    for table in [
        "users",
        "oauth_clients",
        "user_consents",
        "user_sessions",
        "user_totp_factors",
        "user_passkeys",
        "oauth_providers",
        "oauth_external_identities",
        "audit_events",
        "app_settings",
    ] {
        assert!(
            DATABASE_BASELINE.contains(&format!("CREATE TABLE {table} (")),
            "baseline is missing table {table}"
        );
    }
}

#[test]
fn migration_preflight_is_inside_the_sqlx_lock_and_rejects_search_path_workarounds() {
    for marker in [
        "pg_catalog.pg_extension",
        "pg_catalog.pg_namespace",
        ".bind(PG_TRGM_EXTENSION)",
        "ALTER EXTENSION pg_trgm SET SCHEMA public",
        "Changing search_path cannot satisfy this contract",
    ] {
        assert!(
            DB_MIGRATION_PREFLIGHT_MODULE.contains(marker),
            "pg_trgm preflight is missing marker: {marker}"
        );
    }

    let lock = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::lock(&mut *connection).await?;")
        .expect("migration must acquire SQLx's advisory lock");
    let preflight = DB_MIGRATION_COMPAT_MODULE
        .find("migration_preflight::verify(&mut connection).await?;")
        .expect("migration must run the pg_trgm preflight");
    let repair = DB_MIGRATION_COMPAT_MODULE
        .find("repair_flattened_ledger(&mut connection, &migrator).await?")
        .expect("flattened ledger compatibility must remain enabled");
    let description_repair = DB_MIGRATION_COMPAT_MODULE
        .find("repair_oauth_client_description(&mut connection, &migrator).await?")
        .expect("version-47 compatibility must remain enabled");
    let disable_nested_lock = DB_MIGRATION_COMPAT_MODULE
        .find("migrator.set_locking(false);")
        .expect("run_direct must not acquire the SQLx lock twice");
    let run = DB_MIGRATION_COMPAT_MODULE
        .find("migrator.run_direct(&mut *connection).await")
        .expect("migration must run on the preflighted connection");
    let unlock = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::unlock(&mut *connection).await")
        .expect("migration must release SQLx's advisory lock");

    assert!(lock < preflight);
    assert!(preflight < repair);
    assert!(repair < description_repair);
    assert!(description_repair < disable_nested_lock);
    assert!(disable_nested_lock < run);
    assert!(run < unlock);
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("connection.close_on_drop();"));
}

#[test]
fn migration_checksum_manifest_lists_every_sql_file() {
    let manifest = include_str!("../../../migrations/checksums.sha256");
    let listed = manifest
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect::<Vec<_>>();
    let mut on_disk = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    on_disk.sort();
    let mut listed = listed.into_iter().map(str::to_owned).collect::<Vec<_>>();
    listed.sort();
    assert_eq!(
        on_disk, listed,
        "checksum manifest must list every migration"
    );

    // 已发布账本必须是当前清单的严格前缀：已发布迁移字节不可变，dev 上未发布的
    // 迁移允许暂不入账。行数不在这里硬编码——发布分支/标签上账本必须与清单完全
    // 相等，由 CI 的发布门强制，避免账本靠人记忆更新而长期滞后。
    let published = PUBLISHED_MIGRATION_CHECKSUMS.lines().collect::<Vec<_>>();
    let current = manifest.lines().collect::<Vec<_>>();
    assert!(!published.is_empty(), "published ledger must not be empty");
    assert!(published.len() <= current.len());
    assert_eq!(published, current[..published.len()]);
    for marker in [
        "sha256sum -c published-checksums.sha256",
        "published_count=\"$(wc -l < published-checksums.sha256)\"",
        "head -n \"$published_count\" checksums.sha256",
        "refs/heads/releases|refs/tags/v*)",
        "diff -u published-checksums.sha256 checksums.sha256",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI must pin the published migration ledger: {marker}"
        );
    }
}
