use super::{
    AUDIT_ROLE_SEPARATION_ENV, MANAGE_RUNTIME_PASSWORD_ENV, MigrationPlan, MigrationPlanError,
};
use crate::db::{AuditRoleSeparation, RUNTIME_DATABASE_ROLE, RuntimePasswordPolicy};

const OWNER_URL: &str = "postgres://chenxing:owner-secret@127.0.0.1:5432/chenxing_auth";
const RUNTIME_URL: &str = "postgres://chenxing_runtime:runtime-secret@127.0.0.1:5432/chenxing_auth";

fn plan(
    runtime: &str,
    migration: Option<&str>,
    separation: Option<&str>,
) -> Result<MigrationPlan, MigrationPlanError> {
    MigrationPlan::from_values(runtime, migration, separation, None)
}

#[test]
fn separated_roles_are_the_supported_production_posture() {
    let plan = plan(RUNTIME_URL, Some(OWNER_URL), None).expect("separated roles are accepted");
    assert!(plan.roles_separated());
    assert_eq!(plan.runtime_role(), RUNTIME_DATABASE_ROLE);
    assert_eq!(plan.migration_database_url(), OWNER_URL);
    assert_eq!(plan.runtime_database_url(), RUNTIME_URL);
    assert_eq!(plan.separation(), AuditRoleSeparation::Require);
    assert_eq!(plan.password_policy(), RuntimePasswordPolicy::Managed);
}

#[test]
fn missing_migration_url_is_rejected_by_default() {
    // Issue #281：默认部署过去静默降级成"审计只剩触发器"，现在必须失败。
    let error = plan(OWNER_URL, None, None).expect_err("single-role migrate must fail by default");
    assert_eq!(
        error,
        MigrationPlanError::SingleRoleNotAllowed {
            env: AUDIT_ROLE_SEPARATION_ENV
        }
    );
    // 错误消息要给出可执行的出路，且不能泄露连接串。
    let message = error.to_string();
    assert!(message.contains("MIGRATION_DATABASE_URL"));
    assert!(message.contains("allow-single-role"));
    assert!(!message.contains("owner-secret"));
}

#[test]
fn empty_migration_url_counts_as_unset() {
    let error = plan(OWNER_URL, Some("   "), None).expect_err("blank value must not enable separation");
    assert_eq!(
        error,
        MigrationPlanError::SingleRoleNotAllowed {
            env: AUDIT_ROLE_SEPARATION_ENV
        }
    );
}

#[test]
fn explicit_switch_allows_the_single_role_deployment() {
    let plan = plan(OWNER_URL, None, Some("allow-single-role")).expect("explicit opt-in");
    assert!(!plan.roles_separated());
    assert_eq!(plan.runtime_role(), "chenxing");
    assert_eq!(plan.migration_database_url(), OWNER_URL);
    assert_eq!(plan.separation(), AuditRoleSeparation::AllowSingleRole);
    // 单角色部署里 chenxing_runtime 不参与运行，migrate 不该给它设可登录口令。
    assert_eq!(plan.password_policy(), RuntimePasswordPolicy::Unmanaged);
}

#[test]
fn setting_the_same_role_on_both_urls_is_still_a_single_role_deployment() {
    // 判据是角色是否不同，不是变量有没有设置。
    let error =
        plan(OWNER_URL, Some(OWNER_URL), None).expect_err("same role must not pass as separated");
    assert_eq!(
        error,
        MigrationPlanError::SingleRoleNotAllowed {
            env: AUDIT_ROLE_SEPARATION_ENV
        }
    );
    let plan = plan(OWNER_URL, Some(OWNER_URL), Some("allow-single-role")).expect("explicit opt-in");
    assert!(!plan.roles_separated());
}

#[test]
fn separated_roles_require_the_fixed_runtime_role_name() {
    // 迁移 0019 的 GRANT/REVOKE 写死 chenxing_runtime，别的角色名拿不到那条边界。
    let error = plan(
        "postgres://app:app-secret@127.0.0.1:5432/chenxing_auth",
        Some(OWNER_URL),
        None,
    )
    .expect_err("unexpected runtime role must fail");
    assert_eq!(
        error,
        MigrationPlanError::UnexpectedRuntimeRole {
            expected: RUNTIME_DATABASE_ROLE
        }
    );
}

#[test]
fn urls_without_a_role_are_rejected() {
    assert_eq!(
        plan("postgres://127.0.0.1:5432/chenxing_auth", Some(OWNER_URL), None)
            .expect_err("runtime URL without a role"),
        MigrationPlanError::MissingRuntimeRole
    );
    assert_eq!(
        plan(RUNTIME_URL, Some("not a url"), None).expect_err("invalid migration URL"),
        MigrationPlanError::MissingMigrationRole
    );
}

#[test]
fn separation_policy_parsing_is_case_insensitive_and_strict() {
    assert_eq!(
        plan(OWNER_URL, None, Some("  Allow-Single-Role "))
            .expect("case-insensitive")
            .separation(),
        AuditRoleSeparation::AllowSingleRole
    );
    assert_eq!(
        plan(RUNTIME_URL, Some(OWNER_URL), Some("REQUIRE"))
            .expect("case-insensitive")
            .separation(),
        AuditRoleSeparation::Require
    );
    // 拼错的策略值不能静默回退成任一档，否则运维会以为自己配了另一个语义。
    assert_eq!(
        plan(RUNTIME_URL, Some(OWNER_URL), Some("allow")).expect_err("typo must fail"),
        MigrationPlanError::InvalidSeparationPolicy {
            env: AUDIT_ROLE_SEPARATION_ENV
        }
    );
}

#[test]
fn runtime_password_management_can_be_handed_to_external_secret_storage() {
    let plan = MigrationPlan::from_values(RUNTIME_URL, Some(OWNER_URL), None, Some("false"))
        .expect("opt out is valid");
    assert_eq!(plan.password_policy(), RuntimePasswordPolicy::Unmanaged);

    let plan = MigrationPlan::from_values(RUNTIME_URL, Some(OWNER_URL), None, Some(" TRUE "))
        .expect("explicit true is valid");
    assert_eq!(plan.password_policy(), RuntimePasswordPolicy::Managed);

    assert_eq!(
        MigrationPlan::from_values(RUNTIME_URL, Some(OWNER_URL), None, Some("maybe"))
            .expect_err("non-boolean must fail"),
        MigrationPlanError::InvalidPasswordPolicy {
            env: MANAGE_RUNTIME_PASSWORD_ENV
        }
    );
}

#[test]
fn debug_output_never_leaks_connection_credentials() {
    let plan = plan(RUNTIME_URL, Some(OWNER_URL), None).expect("separated roles");
    let rendered = format!("{plan:?}");
    assert!(!rendered.contains("owner-secret"));
    assert!(!rendered.contains("runtime-secret"));
    assert!(rendered.contains(RUNTIME_DATABASE_ROLE));
}
