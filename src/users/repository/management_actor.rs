use crate::sqlx::{Postgres, Transaction};
use crate::users::{
    ActorCredentialError, ManagementActorCredential, ManagementActorValidationError,
    domain::{OwnerTargetAccess, UserId, UserPermission},
};

/// User state read while the management transaction owns the row lock.
#[derive(Debug, Clone)]
pub(crate) struct LockedManagementUser {
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) session_epoch: i64,
}

/// Canonical actor/target lock order shared by every transactional user-management write.
pub(crate) struct ManagementUserLockOrder {
    user_ids: Vec<UserId>,
    target_id: UserId,
    actor_id: Option<UserId>,
    credential: ManagementActorCredential,
}

pub(crate) struct LockedActorTarget {
    pub(crate) target: Option<LockedManagementUser>,
    pub(crate) actor: Option<LockedManagementUser>,
    /// `true` for `ADMIN_TOKEN`, or after locking the exact live `user_sessions` row.
    pub(crate) actor_session_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagementActorRejection {
    SessionInvalid,
    PermissionRequired,
}

/// Acquire every user-level advisory lock before any user row lock.
///
/// Sorting and deduplicating here is the deadlock boundary for A-manages-B / B-manages-A writes.
/// Session issuance and bulk credential revocation use the same per-user advisory lock, so actor
/// generation changes cannot cross this transaction after the scope has been acquired.
pub(crate) async fn lock_management_user_advisories(
    transaction: &mut Transaction<'_, Postgres>,
    target_id: UserId,
    credential: ManagementActorCredential,
) -> Result<ManagementUserLockOrder, crate::sqlx::Error> {
    let actor_id = credential.user_id();
    let mut user_ids = vec![target_id];
    if let Some(actor_id) = actor_id {
        user_ids.push(actor_id);
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    for user_id in &user_ids {
        crate::sessions::store::lock_user_session_scope(transaction, *user_id).await?;
    }
    Ok(ManagementUserLockOrder {
        user_ids,
        target_id,
        actor_id,
        credential,
    })
}

/// Lock actor and target user rows in the same ID order used for their advisory locks,
/// then lock and time-revalidate the exact authenticated `user_sessions` row
/// (Issues #647 / #694).
pub(crate) async fn lock_management_user_rows(
    transaction: &mut Transaction<'_, Postgres>,
    lock_order: &ManagementUserLockOrder,
) -> Result<LockedActorTarget, crate::sqlx::Error> {
    let mut target = None;
    let mut actor = None;
    for user_id in &lock_order.user_ids {
        let state = crate::sqlx::query_as::<_, (String, String, i64)>(
            "SELECT role, status, session_epoch FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(*user_id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|(role, status, session_epoch)| LockedManagementUser {
            role,
            status,
            session_epoch,
        });
        if *user_id == lock_order.target_id {
            target = state.clone();
        }
        if lock_order.actor_id == Some(*user_id) {
            actor = state;
        }
    }
    let actor_session_valid =
        lock_management_actor_session(transaction, lock_order.credential).await?;
    Ok(LockedActorTarget {
        target,
        actor,
        actor_session_valid,
    })
}

/// Lock and revalidate the exact authenticated `user_sessions` row.
///
/// Logout and single-session revoke set `revoked_at` without advancing
/// `users.session_epoch`. Role/status/epoch checks therefore cannot see that the
/// Cookie is dead; this row lock is the authority for that fact (Issue #647).
/// The liveness check runs in a second statement after the row lock is acquired.
/// PostgreSQL `NOW()` is fixed at transaction start, so it cannot detect a Session
/// crossing its absolute or idle deadline while this transaction waits on a lock
/// (Issue #694). `statement_timestamp()` gives the database time at the actual
/// side-effect authorization boundary.
/// `ADMIN_TOKEN` has no session row and returns `true`.
async fn lock_management_actor_session(
    transaction: &mut Transaction<'_, Postgres>,
    credential: ManagementActorCredential,
) -> Result<bool, crate::sqlx::Error> {
    let ManagementActorCredential::UserSession {
        user_id,
        session_id,
        generation,
    } = credential
    else {
        return Ok(true);
    };
    let locked: Option<bool> = crate::sqlx::query_scalar(
        "SELECT TRUE
         FROM user_sessions
         WHERE id = $1
           AND user_id = $2
         FOR UPDATE",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if locked.is_none() {
        return Ok(false);
    }

    crate::sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM user_sessions
             WHERE id = $1
               AND user_id = $2
               AND revoked_at IS NULL
               AND session_epoch = $3
               AND expires_at > statement_timestamp()
               AND last_seen_at > statement_timestamp()
                   - MAKE_INTERVAL(secs => idle_timeout_seconds)
         )",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await
}

pub(crate) fn validate_management_actor(
    credential: ManagementActorCredential,
    locked: &LockedActorTarget,
) -> Result<OwnerTargetAccess, ManagementActorRejection> {
    if matches!(credential, ManagementActorCredential::SystemToken) {
        return Ok(OwnerTargetAccess::ManageRoles);
    }
    if !locked.actor_session_valid {
        return Err(ManagementActorRejection::SessionInvalid);
    }
    let Some(actor) = locked.actor.as_ref() else {
        return Err(ManagementActorRejection::SessionInvalid);
    };
    credential
        .locked_access(&actor.role, &actor.status, actor.session_epoch)
        .map_err(|error| match error {
            ActorCredentialError::SessionInvalid => ManagementActorRejection::SessionInvalid,
            ActorCredentialError::PermissionRequired => {
                ManagementActorRejection::PermissionRequired
            }
        })
}

pub(crate) fn validate_locked_management_actor_permission(
    credential: ManagementActorCredential,
    locked: &LockedActorTarget,
    permission: UserPermission,
) -> Result<(), ManagementActorValidationError> {
    if matches!(credential, ManagementActorCredential::SystemToken) {
        return Ok(());
    }
    if !locked.actor_session_valid {
        return Err(ManagementActorValidationError::SessionInvalid);
    }
    let Some(actor) = locked.actor.as_ref() else {
        return Err(ManagementActorValidationError::SessionInvalid);
    };
    credential
        .validate_locked(&actor.role, &actor.status, actor.session_epoch, permission)
        .map(|_| ())
        .map_err(|error| match error {
            ActorCredentialError::SessionInvalid => ManagementActorValidationError::SessionInvalid,
            ActorCredentialError::PermissionRequired => {
                ManagementActorValidationError::PermissionRequired
            }
        })
}

/// Revalidate an AdminWrite actor while the caller's mutation transaction owns
/// the actor's session-generation lock. No business write may precede this call.
pub(crate) async fn validate_management_actor_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    credential: ManagementActorCredential,
    permission: UserPermission,
) -> Result<(), ManagementActorValidationError> {
    let ManagementActorCredential::UserSession { user_id, .. } = credential else {
        return Ok(());
    };
    crate::sessions::store::lock_user_session_scope(transaction, user_id).await?;
    let actor = crate::sqlx::query_as::<_, (String, String, i64)>(
        "SELECT role, status, session_epoch FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?
    .map(|(role, status, session_epoch)| LockedManagementUser {
        role,
        status,
        session_epoch,
    });
    let actor_session_valid = lock_management_actor_session(transaction, credential).await?;
    validate_locked_management_actor_permission(
        credential,
        &LockedActorTarget {
            target: None,
            actor,
            actor_session_valid,
        },
        permission,
    )
}

#[cfg(test)]
#[path = "management_actor_tests.rs"]
mod tests;
