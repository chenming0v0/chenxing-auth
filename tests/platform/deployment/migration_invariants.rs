use super::{DB_AUDIT_BOUNDARY_MODULE, DB_MIGRATE_MODULE, DB_ROLES_MODULE, ENV_EXAMPLE};

fn migration_history_sql() -> String {
    let mut migrations = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort();
    migrations
        .into_iter()
        .map(|path| std::fs::read_to_string(path).expect("read migration SQL"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn migration_history_declares_final_security_and_consistency_invariants() {
    let history = migration_history_sql();
    for marker in [
        "ADD COLUMN IF NOT EXISTS canonical_email TEXT",
        "ALTER COLUMN canonical_email SET NOT NULL",
        "ALTER COLUMN allow_legacy_refresh_tokens SET DEFAULT FALSE",
        "client_secret_version BIGINT NOT NULL DEFAULT 0",
        "state_version BIGINT NOT NULL DEFAULT 1",
        "CONSTRAINT oauth_providers_active_requires_email_verified_claim",
        "CONSTRAINT session_outbox_state_check",
        "WHERE processed_at IS NULL AND dead_lettered_at IS NULL",
        "CREATE TRIGGER audit_events_append_only_trigger",
        "CREATE TRIGGER audit_events_archive_append_only_trigger",
        "GRANT UPDATE ON SEQUENCE %s TO chenxing_runtime",
        "CREATE TABLE revoked_access_tokens",
        "GRANT SELECT, INSERT, DELETE ON TABLE revoked_access_tokens TO chenxing_runtime",
        "CONSTRAINT oauth_clients_redirect_uris_check",
        "CONSTRAINT oauth_clients_scopes_check",
        "CONSTRAINT user_consents_scopes_check",
        "CONSTRAINT oauth_providers_scopes_check",
        "CONSTRAINT user_passkeys_credential_check",
        "CONSTRAINT user_sessions_idle_timeout_seconds_range",
        "idle_timeout_seconds BIGINT",
        "jsonb_typeof(redirect_uris) = 'array'",
        "jsonb_typeof(credential) = 'object'",
        "CONSTRAINT oauth_clients_auth_method_secret_check",
        "auth_method = 'none' AND client_secret_hash IS NULL",
        "auth_method IN ('client_secret_basic', 'client_secret_post')",
        "CREATE TABLE email_outbox",
        "encrypted_code BYTEA NOT NULL",
        "email_outbox_kind_check",
        "email_outbox_payload_check",
        "email_change_security_alert",
        "num_nonnulls(processed_at, cancelled_at, dead_lettered_at) <= 1",
        "FOREIGN KEY (challenge_id, user_id)",
        "WHERE processed_at IS NULL\n      AND cancelled_at IS NULL\n      AND dead_lettered_at IS NULL",
        "CONSTRAINT user_email_change_attempts_nonnegative",
        "CONSTRAINT user_email_change_attempts_bounded",
        "failed_attempts + in_flight_attempts <= 5",
        "DROP CONSTRAINT user_email_change_attempts_bounded",
        "active_attempt_ids UUID[]",
        "cardinality(active_attempt_ids)",
        "GRANT SELECT, INSERT, UPDATE ON TABLE user_email_change_challenges TO chenxing_runtime",
        "CREATE TABLE user_wallets",
        "CREATE TABLE wallet_ledger",
        "GRANT SELECT, INSERT, UPDATE ON TABLE user_wallets TO chenxing_runtime",
        "GRANT SELECT, INSERT ON TABLE wallet_ledger TO chenxing_runtime",
        "GRANT USAGE, SELECT ON SEQUENCE wallet_ledger_id_seq TO chenxing_runtime",
        "CONSTRAINT plans_price_points_check CHECK (price_points >= 0)",
        "CONSTRAINT plans_billing_period_check CHECK (billing_period IN ('one_time', 'monthly', 'yearly'))",
        "plan_entitlement_version BIGINT NOT NULL DEFAULT 0",
        "CREATE TABLE plan_quota_addons",
        "CREATE TABLE user_quota_addon_purchases",
        "CONSTRAINT plan_quota_addons_id_plan_id_key UNIQUE (id, plan_id)",
        "CONSTRAINT user_quota_addon_addon_plan_fkey",
        "FOREIGN KEY (addon_id, plan_id) REFERENCES plan_quota_addons(id, plan_id) ON DELETE RESTRICT",
        "GRANT SELECT, INSERT, UPDATE ON TABLE plan_quota_addons TO chenxing_runtime",
        "GRANT SELECT, INSERT ON TABLE user_quota_addon_purchases TO chenxing_runtime",
        "GRANT USAGE, SELECT ON SEQUENCE plan_quota_addons_id_seq TO chenxing_runtime",
        "GRANT USAGE, SELECT ON SEQUENCE user_quota_addon_purchases_id_seq TO chenxing_runtime",
        "CREATE TABLE wallet_purchase_idempotency",
        "CONSTRAINT wallet_purchase_idempotency_key_digest_check",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE wallet_purchase_idempotency TO chenxing_runtime",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I._sqlx_migrations",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I.audit_events_archive FROM chenxing_runtime",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES",
    ] {
        assert!(
            history.contains(marker),
            "database migration history is missing invariant: {marker}"
        );
    }
}

#[test]
fn database_baseline_enforces_runtime_role_least_privilege() {
    let history = migration_history_sql();
    for marker in [
        "chenxing_runtime",
        "GRANT USAGE ON SCHEMA",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
        "REVOKE UPDATE, DELETE, TRUNCATE ON",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog",
        "REVOKE ALL ON FUNCTION",
    ] {
        assert!(
            history.contains(marker),
            "database migration history is missing runtime privilege marker: {marker}"
        );
    }
}

/// Issue #281：基线的 REVOKE 只在"运行时角色 ≠ 表 owner"时才是边界。
///
/// 断言写在源码文本上，因为这里要守住的是"迁移命令必须实测权限、不能只相信
/// 迁移文件"这个结构决定。真实权限行为由 `database_schema` 的集成用例覆盖。
#[test]
fn migrate_command_verifies_the_audit_boundary_instead_of_trusting_the_migration() {
    for marker in [
        // 判定依据必须是这条连接上的有效主体，而不是 URL 用户名（Issue #649）。
        "has_table_privilege(",
        "has_function_privilege(",
        "current_user",
        "session_user",
        "EffectiveRoleMismatch",
        "RuntimeRoleCanMutateAudit",
        // 单角色部署要么被拒，要么走显式开关并强告警。
        "AllowSingleRole",
        "DegradedButAllowed",
    ] {
        assert!(
            DB_AUDIT_BOUNDARY_MODULE.contains(marker),
            "audit boundary module is missing marker: {marker}"
        );
    }
    // 运行时口令不能被无条件覆盖。
    for marker in ["PasswordAction::Keep", "MIGRATION_MANAGE_RUNTIME_PASSWORD"] {
        assert!(
            DB_ROLES_MODULE.contains(marker),
            "runtime role module is missing marker: {marker}"
        );
    }
    for marker in [
        "SingleRoleNotAllowed",
        "allow-single-role",
        "MIGRATION_DATABASE_URL",
        "AUDIT_ROLE_SEPARATION",
    ] {
        assert!(
            DB_MIGRATE_MODULE.contains(marker),
            "migration plan module is missing marker: {marker}"
        );
    }

    // 校验必须在 migrate 分支里被调用，否则策略只是个没人读的枚举。
    // Issue #649：必须连 runtime URL 再验，不能在 owner 连接上拿 URL 用户名做目录检查。
    let main = include_str!("../../../src/main.rs");
    assert!(main.contains("db::MigrationPlan::from_env("));
    assert!(main.contains("db::verify_audit_append_only_boundary("));
    assert!(main.contains("connect_maintenance(plan.runtime_database_url())"));

    for marker in [
        "AUDIT_ROLE_SEPARATION",
        "MIGRATION_MANAGE_RUNTIME_PASSWORD",
        "allow-single-role",
    ] {
        assert!(
            ENV_EXAMPLE.contains(marker),
            ".env.example must document the audit role separation controls: {marker}"
        );
    }
}
