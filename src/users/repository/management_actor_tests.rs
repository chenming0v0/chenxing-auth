use super::*;
use crate::users::domain::OwnerTargetAccess;

fn admin_credential() -> ManagementActorCredential {
    ManagementActorCredential::UserSession {
        user_id: 11,
        session_id: 42,
        generation: 3,
    }
}

fn active_admin() -> LockedManagementUser {
    LockedManagementUser {
        role: "admin".to_owned(),
        status: "active".to_owned(),
        session_epoch: 3,
    }
}

fn actor_target(
    actor: Option<LockedManagementUser>,
    actor_session_valid: bool,
) -> LockedActorTarget {
    LockedActorTarget {
        target: None,
        actor,
        actor_session_valid,
    }
}

/// Issue #647: a revoked or missing session row must fail closed even when the
/// user is still active and the epoch still matches the Cookie.
#[test]
fn revoked_session_is_rejected_when_user_epoch_still_matches() {
    let locked = actor_target(Some(active_admin()), false);
    assert_eq!(
        validate_management_actor(admin_credential(), &locked),
        Err(ManagementActorRejection::SessionInvalid)
    );
    assert!(matches!(
        validate_locked_management_actor_permission(
            admin_credential(),
            &locked,
            UserPermission::ManageUsers,
        ),
        Err(ManagementActorValidationError::SessionInvalid)
    ));
}

/// A different still-valid session for the same user must keep working.
/// Single-session revoke must not be implemented as a hidden epoch bump.
#[test]
fn live_session_still_authorizes_when_user_epoch_is_unchanged() {
    let locked = actor_target(Some(active_admin()), true);
    assert_eq!(
        validate_management_actor(admin_credential(), &locked),
        Ok(OwnerTargetAccess::ManageUsers)
    );
    assert!(
        validate_locked_management_actor_permission(
            admin_credential(),
            &locked,
            UserPermission::ManageUsers,
        )
        .is_ok()
    );
}

#[test]
fn system_token_does_not_depend_on_a_session_row() {
    let locked = actor_target(None, true);
    assert_eq!(
        validate_management_actor(ManagementActorCredential::SystemToken, &locked),
        Ok(OwnerTargetAccess::ManageRoles)
    );
}
