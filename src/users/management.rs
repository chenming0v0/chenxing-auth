use super::domain::{UserId, UserPermission, UserRole, UserStatus};
use crate::sqlx::PgPool;

/// Credential that authorizes a high-risk management write (Issues #493 / #647).
///
/// A browser request carries the identity and generation of the exact Session Cookie that
/// authenticated it. The write transaction locks that user **and** that `user_sessions` row,
/// then rechecks status, role, generation, and revocation before touching the target.
/// Single-session logout sets `revoked_at` without advancing `users.session_epoch`, so the
/// row identity is the only way to see that the Cookie is dead. The deployment `ADMIN_TOKEN`
/// is deliberately separate: it has no user row or Session and follows explicit system-actor
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementActorCredential {
    UserSession {
        user_id: UserId,
        session_id: i64,
        generation: i64,
    },
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
        let role = self.validate_locked(role, status, generation, UserPermission::ManageUsers)?;
        Ok(if role.allows(UserPermission::ManageRoles) {
            super::domain::OwnerTargetAccess::ManageRoles
        } else {
            super::domain::OwnerTargetAccess::ManageUsers
        })
    }

    pub(crate) fn validate_locked(
        self,
        role: &str,
        status: &str,
        generation: i64,
        permission: UserPermission,
    ) -> Result<UserRole, ActorCredentialError> {
        let Self::UserSession {
            generation: expected,
            ..
        } = self
        else {
            return Ok(UserRole::Owner);
        };
        if UserStatus::parse(status) != Some(UserStatus::Active) || generation != expected {
            return Err(ActorCredentialError::SessionInvalid);
        }
        let Some(role) = UserRole::parse(role) else {
            return Err(ActorCredentialError::PermissionRequired);
        };
        if !role.allows(permission) {
            return Err(ActorCredentialError::PermissionRequired);
        }
        Ok(role)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActorCredentialError {
    SessionInvalid,
    PermissionRequired,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagementActorValidationError {
    #[error("the management actor session is no longer valid")]
    SessionInvalid,
    #[error("the management actor no longer has the required permission")]
    PermissionRequired,
    #[error("could not validate the management actor")]
    Database(#[from] crate::sqlx::Error),
}

/// Recheck the AdminWrite actor in a dedicated transaction before a
/// non-transactional side effect. `ADMIN_TOKEN` has no user row and returns
/// immediately. Residual TOCTOU after commit is accepted; callers must not
/// hold a user lock across blocking IO.
pub(crate) async fn revalidate_management_actor(
    pool: &PgPool,
    credential: ManagementActorCredential,
    permission: UserPermission,
) -> Result<(), ManagementActorValidationError> {
    if matches!(credential, ManagementActorCredential::SystemToken) {
        return Ok(());
    }
    let mut transaction = pool.begin().await?;
    super::repository::management_actor::validate_management_actor_in_transaction(
        &mut transaction,
        credential,
        permission,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}
