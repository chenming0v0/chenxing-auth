use super::{
    AuditBoundaryVerdict, AuditPrivileges, AuditRoleSeparation, audit_boundary_verdict,
    principal_matches,
};

fn separated() -> AuditPrivileges {
    AuditPrivileges {
        can_insert: true,
        can_select: true,
        can_archive: true,
        can_mutate: false,
    }
}

fn single_role() -> AuditPrivileges {
    AuditPrivileges {
        can_mutate: true,
        ..separated()
    }
}

#[test]
fn boundary_is_enforced_when_the_runtime_role_cannot_mutate_audit() {
    for separation in [
        AuditRoleSeparation::Require,
        AuditRoleSeparation::AllowSingleRole,
    ] {
        assert_eq!(
            audit_boundary_verdict(separated(), true, separation),
            AuditBoundaryVerdict::Enforced
        );
    }
}

#[test]
fn single_role_deployment_is_rejected_by_default() {
    // 默认策略下"迁移角色 == 运行时角色"必须失败，而不是静默声称隔离有效。
    // 归档 INSERT 也走同一条 can_mutate 路径（Issue #648）。
    assert_eq!(
        audit_boundary_verdict(single_role(), true, AuditRoleSeparation::Require),
        AuditBoundaryVerdict::Violated
    );
}

#[test]
fn single_role_deployment_is_allowed_only_with_the_explicit_switch() {
    assert_eq!(
        audit_boundary_verdict(single_role(), true, AuditRoleSeparation::AllowSingleRole),
        AuditBoundaryVerdict::DegradedButAllowed
    );
}

#[test]
fn mismatched_principal_is_a_violation_even_when_the_named_role_cannot_mutate() {
    // URL 写 chenxing_runtime、连接上 current_user 却是 owner：目录里那个名字
    // 仍然不能改表，但有效主体可以。Require 必须拒绝（Issue #649）。
    assert_eq!(
        audit_boundary_verdict(separated(), false, AuditRoleSeparation::Require),
        AuditBoundaryVerdict::Violated
    );
}

#[test]
fn mismatched_principal_is_degraded_only_with_the_explicit_switch() {
    assert_eq!(
        audit_boundary_verdict(separated(), false, AuditRoleSeparation::AllowSingleRole),
        AuditBoundaryVerdict::DegradedButAllowed
    );
}

#[test]
fn principal_must_match_both_current_user_and_session_user() {
    assert!(principal_matches(
        "chenxing_runtime",
        "chenxing_runtime",
        "chenxing_runtime"
    ));
    // SET ROLE owner after logging in as runtime: session_user still matches.
    assert!(!principal_matches(
        "chenxing",
        "chenxing_runtime",
        "chenxing_runtime"
    ));
    // Login as owner then SET ROLE runtime: current_user looks restricted.
    assert!(!principal_matches(
        "chenxing_runtime",
        "chenxing",
        "chenxing_runtime"
    ));
    assert!(!principal_matches(
        "chenxing",
        "chenxing",
        "chenxing_runtime"
    ));
}

#[test]
fn separation_policy_names_match_the_documented_values() {
    assert_eq!(AuditRoleSeparation::Require.as_str(), "require");
    assert_eq!(
        AuditRoleSeparation::AllowSingleRole.as_str(),
        "allow-single-role"
    );
}
