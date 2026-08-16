//! Persist a new session under Postgres authority (Issue #466).
//!
//! The payload must contain the final row id, so issuance cannot learn the id
//! from `RETURNING` after encrypting. This module reserves the identity
//! sequence value first, encrypts once, and inserts the row and outbox event
//! in the same transaction. There is no `session_payload = NULL` placeholder
//! and no follow-up UPDATE on the new row.

use std::time::Duration;

use crate::{
    sessions::domain::{Session, SessionPayload, session_token_hash_bytes},
    sqlx::{Postgres, Transaction},
    users::domain::{UserId, UserStatus},
};

use super::super::{
    EffectiveFactorState, PasswordSessionPersistence, SessionEpochBinding, SessionStore,
    SessionStoreError,
};

/// 写入会话元数据。
///
/// `binding` 为 [`SessionEpochBinding::Authenticated`] 时，epoch 比对发生在本事务
/// 已经持有该用户的 advisory 锁与 `users` 行锁之后（Issue #274）。这一点是原子性的
/// 全部来源：改密走的 `revoke_all_for_user_in_transaction` 需要同一把 advisory 锁，
/// 因此两个事务只能串行——要么改密先提交、本次读到新 epoch 并拒绝写入，要么本次
/// 先提交、改密随后把这条会话一起撤销。不存在"读到旧 epoch 又按新 epoch 落库"的
/// 中间态。比对失败直接返回错误，事务连一行都没插入。
pub(super) async fn save_with_metadata(
    store: &SessionStore,
    session: &mut Session,
    _ttl: Duration,
    binding: SessionEpochBinding,
) -> Result<PasswordSessionPersistence, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| SessionStoreError::InvalidUserId)?;
    let token_hash = session_token_hash_bytes(&session.token).to_vec();
    let mut transaction = pool.begin().await?;
    if matches!(binding, SessionEpochBinding::PasswordAuthenticated { .. }) {
        crate::settings::repository::lock_passkey_policy(&mut *transaction).await?;
    }
    super::lock_user_session_scope(&mut transaction, user_id).await?;
    let user_state: Option<(i64, String)> =
        crate::sqlx::query_as("SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some((session_epoch, status)) = user_state else {
        return Err(SessionStoreError::UserNotFound);
    };
    if UserStatus::parse(&status) != Some(UserStatus::Active) {
        return Err(SessionStoreError::UserDisabled);
    }
    let authenticated_epoch = match binding {
        SessionEpochBinding::Current => None,
        SessionEpochBinding::Authenticated(epoch)
        | SessionEpochBinding::PasswordAuthenticated {
            authenticated_epoch: epoch,
            ..
        } => Some(epoch),
    };
    if authenticated_epoch.is_some_and(|epoch| epoch != session_epoch) {
        tracing::warn!(
            event = "session.authentication_epoch_stale",
            user_id,
            "session issuance rejected because credentials were invalidated concurrently"
        );
        return Err(SessionStoreError::AuthenticationEpochChanged);
    }
    if let SessionEpochBinding::PasswordAuthenticated { .. } = binding {
        let factors: (bool, bool) = crate::sqlx::query_as(
            "SELECT
                 EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1),
                 EXISTS(SELECT 1 FROM user_passkeys WHERE user_id = $1)",
        )
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await?;
        let passkey_enabled = match crate::settings::repository::get_text(
            &mut *transaction,
            crate::settings::PASSKEY_KEY,
        )
        .await?
        {
            None => true,
            Some(raw) => serde_json::from_str::<crate::settings::PasskeySetting>(&raw)
                .map(|setting| setting.enabled)
                .unwrap_or(false),
        };
        let effective = EffectiveFactorState {
            totp: factors.0,
            passkey: passkey_enabled && factors.1,
        };
        if effective.totp || effective.passkey {
            transaction.rollback().await?;
            return Ok(PasswordSessionPersistence::FactorBecameRequired(effective));
        }
    }
    evict_overflow_sessions(store, &mut transaction, user_id, session_epoch).await?;
    let id = insert_new_session(
        store,
        &mut transaction,
        session,
        user_id,
        &token_hash,
        session_epoch,
    )
    .await?;
    transaction.commit().await?;
    // Publish the durable identity only after commit so a rolled-back insert
    // cannot leak a sequence value into the caller-visible Session.
    session.id = id;
    session.set_credential_generation(session_epoch);
    Ok(PasswordSessionPersistence::Stored)
}

async fn evict_overflow_sessions(
    store: &SessionStore,
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    session_epoch: i64,
) -> Result<(), SessionStoreError> {
    let active_count: i64 = crate::sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM user_sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND expires_at > NOW()
           AND last_seen_at > NOW() - $2
           AND session_epoch >= $3",
    )
    .bind(user_id)
    .bind(store.idle_timeout_interval())
    .bind(session_epoch)
    .fetch_one(&mut **transaction)
    .await?;
    let max_sessions = i64::try_from(store.policy.max_concurrent_sessions).unwrap_or(i64::MAX);
    let revoke_count = active_count
        .saturating_sub(max_sessions.saturating_sub(1))
        .max(0);
    let active_sessions: Vec<(i64, Vec<u8>)> = if revoke_count == 0 {
        Vec::new()
    } else {
        crate::sqlx::query_as(
            "SELECT id, token_hash
             FROM user_sessions
             WHERE user_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()
               AND last_seen_at > NOW() - $2
               AND session_epoch >= $3
             ORDER BY created_at ASC, id ASC
             LIMIT $4
             FOR UPDATE",
        )
        .bind(user_id)
        .bind(store.idle_timeout_interval())
        .bind(session_epoch)
        .bind(revoke_count)
        .fetch_all(&mut **transaction)
        .await?
    };
    for (session_id, old_token_hash) in active_sessions {
        crate::sqlx::query(
            "UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE id = $1",
        )
        .bind(session_id)
        .execute(&mut **transaction)
        .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox
                 (operation, session_id, user_id, token_hash, generation)
             VALUES ('revoke_session', $1, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(old_token_hash)
        .bind(session_epoch)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Reserve the final `user_sessions.id`, encrypt a payload that already
/// contains it, and insert the row plus its sync outbox event.
///
/// `user_sessions.id` is `GENERATED ALWAYS AS IDENTITY`, so the INSERT names
/// the preallocated value with `OVERRIDING SYSTEM VALUE`. Sequence values do
/// not roll back; the caller must not copy this id onto `Session` until the
/// surrounding transaction commits.
async fn insert_new_session(
    store: &SessionStore,
    transaction: &mut Transaction<'_, Postgres>,
    session: &Session,
    user_id: UserId,
    token_hash: &[u8],
    session_epoch: i64,
) -> Result<i64, SessionStoreError> {
    let id: i64 = crate::sqlx::query_scalar(
        "SELECT nextval(pg_get_serial_sequence('user_sessions', 'id'))",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let mut stored_payload = SessionPayload::from(session);
    stored_payload.id = id;
    let encrypted_payload = store.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
    crate::sqlx::query(
        "INSERT INTO user_sessions
             (id, token_hash, user_id, created_at, expires_at, last_seen_at,
              session_payload, session_epoch)
         OVERRIDING SYSTEM VALUE
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(token_hash)
    .bind(user_id)
    .bind(session.created_at)
    .bind(session.expires_at)
    .bind(session.last_seen_at)
    .bind(encrypted_payload)
    .bind(session_epoch)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         VALUES ('sync_session', $1, $2, $3, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(session_epoch)
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}
