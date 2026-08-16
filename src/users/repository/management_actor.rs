use crate::sqlx::{Postgres, Transaction};
use crate::users::{
    ActorCredentialError, ManagementActorCredential,
    domain::{OwnerTargetAccess, UserId},
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
}

pub(crate) struct LockedActorTarget {
    pub(crate) target: Option<LockedManagementUser>,
    pub(crate) actor: Option<LockedManagementUser>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagementActorRejection {
    SessionInvalid,
    PermissionRequired,
}

/// Acquire every user-level advisory lock before any user row lock.
///
/// Sorting and deduplicating here is the deadlock boundary for A-manages-B / B-manages-A writes.
/// Session issuance and credential revocation use the same per-user advisory lock, so actor
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
    })
}

/// Lock actor and target rows in the same ID order used for their advisory locks.
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
    Ok(LockedActorTarget { target, actor })
}

pub(crate) fn validate_management_actor(
    credential: ManagementActorCredential,
    actor: Option<&LockedManagementUser>,
) -> Result<OwnerTargetAccess, ManagementActorRejection> {
    if matches!(credential, ManagementActorCredential::SystemToken) {
        return Ok(OwnerTargetAccess::ManageRoles);
    }
    let Some(actor) = actor else {
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
