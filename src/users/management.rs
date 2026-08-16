use super::domain::{UserId, UserPermission, UserRole, UserStatus};

/// Credential that authorizes a high-risk management write (Issue #493).
///
/// A browser request carries the generation of the exact Session Cookie that authenticated it.
/// The write transaction locks that user and rechecks status, role, and generation before touching
/// the target. The deployment `ADMIN_TOKEN` is deliberately separate: it has no user row or
/// Session generation and follows explicit system-actor semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementActorCredential {
    UserSession { user_id: UserId, generation: i64 },
    SystemToken,
}

impl ManagementActorCredential {
    pub const fn user_id(self) -> Option<UserId> {
        match self {
            Self::UserSession { user_id, .. } => Some(user_id),
            Self::SystemToken => None,
        }
    }

    pub(crate) fn locked_access(
        self,
        role: &str,
        status: &str,
        generation: i64,
    ) -> Result<super::domain::OwnerTargetAccess, ActorCredentialError> {
        let Self::UserSession {
            generation: expected,
            ..
        } = self
        else {
            return Ok(super::domain::OwnerTargetAccess::ManageRoles);
        };
        if UserStatus::parse(status) != Some(UserStatus::Active) || generation != expected {
            return Err(ActorCredentialError::SessionInvalid);
        }
        let Some(role) = UserRole::parse(role) else {
            return Err(ActorCredentialError::PermissionRequired);
        };
        if !role.allows(UserPermission::ManageUsers) {
            return Err(ActorCredentialError::PermissionRequired);
        }
        Ok(if role.allows(UserPermission::ManageRoles) {
            super::domain::OwnerTargetAccess::ManageRoles
        } else {
            super::domain::OwnerTargetAccess::ManageUsers
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActorCredentialError {
    SessionInvalid,
    PermissionRequired,
}
