use super::{AuditBoundaryVerdict, AuditPrivileges, AuditRoleSeparation, audit_boundary_verdict};

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
            audit_boundary_verdict(separated(), separation),
            AuditBoundaryVerdict::Enforced
        );
    }
}

#[test]
fn single_role_deployment_is_rejected_by_default() {
    // 默认策略下"迁移角色 == 运行时角色"必须失败，而不是静默声称隔离有效。
    assert_eq!(
        audit_boundary_verdict(single_role(), AuditRoleSeparation::Require),
        AuditBoundaryVerdict::Violated
    );
}

#[test]
fn single_role_deployment_is_allowed_only_with_the_explicit_switch() {
    assert_eq!(
        audit_boundary_verdict(single_role(), AuditRoleSeparation::AllowSingleRole),
        AuditBoundaryVerdict::DegradedButAllowed
    );
}

#[test]
fn separation_policy_names_match_the_documented_values() {
    assert_eq!(AuditRoleSeparation::Require.as_str(), "require");
    assert_eq!(
        AuditRoleSeparation::AllowSingleRole.as_str(),
        "allow-single-role"
    );
}
