pub(super) fn embedded_migrator() -> crate::sqlx::migrate::Migrator {
    use super::normalize_migration_sql;
    use crate::sqlx::migrate::{Migration, MigrationType, Migrator};
    use std::borrow::Cow;

    // Versions 1-27 have shipped and their SQL bytes are immutable. Keeping every
    // historical step here lets SQLx validate an existing database and continue
    // forward instead of treating the latest schema as a replacement version 1.
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
        (
            28,
            "controlled runtime issuer",
            include_str!("../../migrations/0028_issuer_runtime.sql"),
        ),
        (
            29,
            "bounded plan quotas",
            include_str!("../../migrations/0029_plan_quota_bounds.sql"),
        ),
        (
            30,
            "passkey state version",
            include_str!("../../migrations/0030_passkey_state_version.sql"),
        ),
        (
            31,
            "client operation idempotency",
            include_str!("../../migrations/0031_client_operation_idempotency.sql"),
        ),
        (
            32,
            "runtime migration ledger boundary",
            include_str!("../../migrations/0032_runtime_migration_ledger_boundary.sql"),
        ),
        (
            33,
            "registration invitation codes",
            include_str!("../../migrations/0033_registration_invitation_codes.sql"),
        ),
        (
            34,
            "user email change challenges",
            include_str!("../../migrations/0034_user_email_change_challenges.sql"),
        ),
        (
            35,
            "session outbox claim fence",
            include_str!("../../migrations/0035_session_outbox_claim_fence.sql"),
        ),
        (
            36,
            "revoke runtime archive insert",
            include_str!("../../migrations/0036_revoke_runtime_archive_insert.sql"),
        ),
        (
            37,
            "revoked access tokens",
            include_str!("../../migrations/0037_revoked_access_tokens.sql"),
        ),
        (
            38,
            "jsonb oauth consent shapes",
            include_str!("../../migrations/0038_jsonb_oauth_consent_shapes.sql"),
        ),
        (
            39,
            "session issued idle timeout",
            include_str!("../../migrations/0039_session_issued_idle_timeout.sql"),
        ),
        (
            40,
            "oauth client auth method secret",
            include_str!("../../migrations/0040_oauth_client_auth_method_secret.sql"),
        ),
        (
            41,
            "email change attempt budget",
            include_str!("../../migrations/0041_email_change_attempt_budget.sql"),
        ),
        (
            42,
            "fix email change attempt budget",
            include_str!("../../migrations/0042_email_change_attempt_budget_fix.sql"),
        ),
        (
            43,
            "email outbox",
            include_str!("../../migrations/0043_email_outbox.sql"),
        ),
        (
            44,
            "oauth provider state version",
            include_str!("../../migrations/0044_oauth_provider_state_version.sql"),
        ),
        (
            45,
            "email security alert outbox",
            include_str!("../../migrations/0045_email_security_alert_outbox.sql"),
        ),
        (
            46,
            "oauth client presentation",
            include_str!("../../migrations/0046_oauth_client_presentation.sql"),
        ),
        (
            47,
            "oauth client description",
            include_str!("../../migrations/0047_oauth_client_description.sql"),
        ),
        (
            48,
            "wallet and plan pricing",
            include_str!("../../migrations/0048_wallet_and_plan_pricing.sql"),
        ),
        (
            49,
            "wallet redemption codes",
            include_str!("../../migrations/0049_wallet_redemption_codes.sql"),
        ),
        (
            50,
            "quota add-ons",
            include_str!("../../migrations/0050_quota_addons.sql"),
        ),
        (
            51,
            "wallet purchase idempotency",
            include_str!("../../migrations/0051_wallet_purchase_idempotency.sql"),
        ),
        (
            52,
            "external identity snapshots",
            include_str!("../../migrations/0052_external_identity_snapshots.sql"),
        ),
        (
            53,
            "cltermux linked accounts",
            include_str!("../../migrations/0053_cltermux_linked_accounts.sql"),
        ),
        (
            54,
            "account provider registry",
            include_str!("../../migrations/0054_account_provider_registry.sql"),
        ),
        (
            55,
            "client numeric app id",
            include_str!("../../migrations/0055_client_numeric_app_id.sql"),
        ),
        (
            56,
            "client owner backfill",
            include_str!("../../migrations/0056_client_owner_backfill.sql"),
        ),
        (
            57,
            "client quota exempt",
            include_str!("../../migrations/0057_client_quota_exempt.sql"),
        ),
        (
            58,
            "account portal consumer tables",
            include_str!("../../migrations/0058_account_portal.sql"),
        ),
        (
            59,
            "resource services rename and scope declaration",
            include_str!("../../migrations/0059_resource_services.sql"),
        ),
        (
            60,
            "audit archive search path",
            include_str!("../../migrations/0060_audit_archive_search_path.sql"),
        ),
        (
            61,
            "email outbox failure budget",
            include_str!("../../migrations/0061_email_outbox_failure_budget.sql"),
        ),
        (
            62,
            "resource service snapshot revision",
            include_str!("../../migrations/0062_resource_service_snapshot_revision.sql"),
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
