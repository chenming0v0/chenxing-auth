use super::domain::{UserId, UserPermission, UserRole, UserStatus};
use crate::sqlx::{PgPool, Postgres, Transaction};
use std::fmt;

/// The exact browser Session credential observed by the request extractor.
///
/// High-risk user mutations carry this proof into their write transaction so a
/// Session revoked, expired, or invalidated after request entry cannot authorize
/// a wallet debit or entitlement grant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserSessionCredential {
    pub(crate) user_id: UserId,
    pub(crate) session_id: i64,
    pub(crate) generation: i64,
    token_hash: [u8; 32],
}

impl UserSessionCredential {
    /// Capture the non-secret identity of an authoritative persisted Session.
    ///
    /// A freshly constructed in-memory Session has no database id or generation
    /// and therefore cannot authorize a high-risk mutation.
    pub fn from_session(
        user_id: UserId,
        session: &crate::sessions::domain::Session,
    ) -> Option<Self> {
        if session.id <= 0 || session.user_id.parse::<UserId>().ok() != Some(user_id) {
            return None;
        }
        Some(Self {
            user_id,
            session_id: session.id,
            generation: session.credential_generation()?,
            token_hash: crate::sessions::domain::session_token_hash_bytes(&session.token),
        })
    }
}

impl fmt::Debug for UserSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserSessionCredential")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("token_hash", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserSessionValidation {
    Valid,
    SessionInvalid,
    UserDisabled,
}

/// Revalidate the exact browser Session while the mutation transaction owns
/// the user-generation lock. Revocation and status changes use the same lock,
/// so whichever transaction acquires it first defines the linearization point.
pub(crate) async fn validate_user_session_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    credential: UserSessionCredential,
) -> Result<UserSessionValidation, crate::sqlx::Error> {
    crate::sessions::store::lock_user_session_scope(transaction, credential.user_id).await?;

    let Some((status, user_epoch)) = crate::sqlx::query_as::<_, (String, i64)>(
        "SELECT status, session_epoch FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(credential.user_id)
    .fetch_optional(&mut **transaction)
    .await?
    else {
        return Ok(UserSessionValidation::SessionInvalid);
    };

    if status == UserStatus::Disabled.as_str() {
        return Ok(UserSessionValidation::UserDisabled);
    }
    if UserStatus::parse(&status) != Some(UserStatus::Active) || user_epoch != credential.generation
    {
        return Ok(UserSessionValidation::SessionInvalid);
    }

    let session_active: Option<bool> = crate::sqlx::query_scalar(
        "SELECT TRUE
         FROM user_sessions
         WHERE id = $1
           AND user_id = $2
           AND token_hash = $3
           AND revoked_at IS NULL
           AND expires_at > statement_timestamp()
           AND last_seen_at > statement_timestamp() - MAKE_INTERVAL(secs => idle_timeout_seconds)
           AND session_epoch = $4
         FOR UPDATE",
    )
    .bind(credential.session_id)
    .bind(credential.user_id)
    .bind(credential.token_hash.as_slice())
    .bind(credential.generation)
    .fetch_optional(&mut **transaction)
    .await?;

    Ok(if session_active.is_some() {
        UserSessionValidation::Valid
    } else {
        UserSessionValidation::SessionInvalid
    })
}

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
