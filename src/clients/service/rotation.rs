//! Client Secret rotation and refresh-token revocation.

use super::{ClientService, ClientServiceError, RotatedClientSecret};
use crate::clients::{
    credentials::{generate_client_secret, hash_client_secret},
    idempotency::{ClientIdempotencyContext, ClientIdempotencyError, IdempotencyKey},
    repository,
};
use crate::users::domain::UserId;

impl ClientService {
    pub async fn rotate_secret(
        &self,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_in_scope(None, client_id).await
    }

    pub async fn rotate_secret_with_audit(
        &self,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_in_scope_with_audit(None, client_id, audit_event)
            .await
    }

    pub async fn rotate_secret_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_in_scope(Some(owner_user_id), client_id)
            .await
    }

    async fn rotate_secret_in_scope(
        &self,
        owner_user_id: Option<UserId>,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let Some(expected_version) =
            repository::find_client_secret_version(&self.pool, owner_user_id, client_id).await?
        else {
            return Err(ClientServiceError::InvalidData);
        };
        let (client_secret, hash) = generate_client_secret()?;
        if !repository::update_client_secret_if_version(
            &self.pool,
            owner_user_id,
            client_id,
            expected_version,
            &hash,
        )
        .await?
        {
            return Err(ClientServiceError::SecretRotationConflict);
        }
        // Token persistence holds a conflicting PostgreSQL FOR SHARE lock while
        // writing Redis. Therefore every old-version token is indexed before
        // this UPDATE can commit and is visible to the cleanup below; a writer
        // arriving after commit fails its version fence instead (Issue #310).
        self.revoke_refresh_tokens_best_effort(
            client_id,
            RefreshTokenCleanupReason::SecretRotation,
        )
        .await;
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }

    pub async fn rotate_secret_for_user_with_audit(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_in_scope_with_audit(Some(owner_user_id), client_id, audit_event)
            .await
    }

    pub async fn rotate_secret_with_audit_idempotent(
        &self,
        client_id: &str,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_idempotent(None, client_id, actor_scope, key, audit_event)
            .await
    }

    pub async fn rotate_secret_for_user_with_audit_idempotent(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        self.rotate_secret_idempotent(
            Some(owner_user_id),
            client_id,
            actor_scope,
            key,
            audit_event,
        )
        .await
    }

    async fn rotate_secret_idempotent(
        &self,
        owner_user_id: Option<UserId>,
        client_id: &str,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let Some(expected_version) =
            repository::find_client_secret_version(&self.pool, owner_user_id, client_id).await?
        else {
            return Err(ClientServiceError::InvalidData);
        };
        let context = ClientIdempotencyContext::for_rotation(actor_scope, key, client_id);
        let keys = self
            .idempotency_keys
            .as_ref()
            .ok_or(ClientServiceError::IdempotencyKeyUnavailable)?;
        let active_kid = keys.active_kid().to_owned();
        let client_secret = context
            .derive_secret(keys, &active_kid)
            .map_err(map_idempotency_crypto_error)?;
        let hash = hash_client_secret(&client_secret)?;
        let persisted = repository::rotate_client_secret_idempotent_with_audit(
            &self.pool,
            repository::IdempotentClientRotation {
                owner_user_id,
                client_id,
                expected_version,
                client_secret_hash: &hash,
                context: &context,
                active_secret_kid: &active_kid,
                audit_event,
            },
        )
        .await;
        let persisted = match persisted {
            Ok(value) => value,
            Err(repository::IdempotentClientOperationError::MutationConflict) => {
                return Err(ClientServiceError::SecretRotationConflict);
            }
            Err(repository::IdempotentClientOperationError::IdempotencyConflict) => {
                return Err(ClientServiceError::IdempotencyConflict);
            }
            Err(repository::IdempotentClientOperationError::CorruptResult) => {
                return Err(ClientServiceError::IdempotencyCorruptResult);
            }
            Err(repository::IdempotentClientOperationError::Database(error)) => {
                return Err(ClientServiceError::Database(error));
            }
            Err(repository::IdempotentClientOperationError::Audit(error)) => {
                tracing::error!(event = "client_secret_rotate.audit_unavailable", error = %error);
                return Err(ClientServiceError::AuditUnavailable);
            }
            Err(repository::IdempotentClientOperationError::QuotaExceeded) => {
                return Err(ClientServiceError::QuotaExceeded);
            }
        };
        self.revoke_refresh_tokens_best_effort(
            client_id,
            RefreshTokenCleanupReason::SecretRotation,
        )
        .await;
        let client_secret = context
            .derive_secret(keys, &persisted.secret_kid)
            .map_err(map_idempotency_crypto_error)?;
        Ok(RotatedClientSecret {
            client_id: persisted.value.client_id,
            client_secret,
        })
    }

    async fn rotate_secret_in_scope_with_audit(
        &self,
        owner_user_id: Option<UserId>,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let Some(expected_version) =
            repository::find_client_secret_version(&self.pool, owner_user_id, client_id).await?
        else {
            return Err(ClientServiceError::InvalidData);
        };
        let (client_secret, hash) = generate_client_secret()?;
        match repository::update_client_secret_if_version_with_audit(
            &self.pool,
            owner_user_id,
            client_id,
            expected_version,
            &hash,
            audit_event,
        )
        .await
        {
            Ok(true) => {
                self.revoke_refresh_tokens_best_effort(
                    client_id,
                    RefreshTokenCleanupReason::SecretRotation,
                )
                .await;
                Ok(RotatedClientSecret {
                    client_id: client_id.to_owned(),
                    client_secret,
                })
            }
            Ok(false) => Err(ClientServiceError::SecretRotationConflict),
            Err(repository::AuditedRotationError::Database(error)) => {
                Err(ClientServiceError::Database(error))
            }
            Err(repository::AuditedRotationError::Audit(error)) => {
                tracing::error!(event = "client_secret_rotate.audit_unavailable", error = %error);
                Err(ClientServiceError::AuditUnavailable)
            }
        }
    }

    /// Secret 轮换后撤销该 Client 的全部 Refresh Token（Issue #62）。
    ///
    /// 版本不匹配已经负责语义上的失效；这里仍立即删除 Redis 记录，避免无效
    /// 凭据占据索引和 TTL，并让正常请求尽快走既有的 token-not-found 路径。
    ///
    /// **故意不回滚 secret**（设计决策 §4）：新 secret 已经写入数据库并生效，
    /// 回滚会让「轮换没生效」这个更危险的状态被静默掩盖。Issue #310 起，
    /// 轮换同时关闭 legacy token 兼容位；新版 Refresh Token 自带 secret version，
    /// 兑换时还会复核。因此撤销失败只留下不可兑换的物理记录，不会让旧授权
    /// 复活；这里的删除仍用于及时清理。
    ///
    /// 同理，撤销失败不改变函数返回值：调用方必须拿到新 secret，
    /// 否则该 Client 会因为「新 secret 已生效但调用者不知道」而完全无法认证。
    pub(super) async fn revoke_refresh_tokens_best_effort(
        &self,
        client_id: &str,
        reason: RefreshTokenCleanupReason,
    ) {
        let Some(store) = self.refresh_tokens.as_ref() else {
            // 未注入存储属于装配错误（生产路径一定会注入）。
            // 记 error 而不是静默积累无效凭据。
            tracing::error!(
                client_id = %client_id,
                reason = reason.as_str(),
                "client lifecycle event without refresh token store; \
                 stale refresh token records could not be eagerly removed"
            );
            return;
        };
        match store.revoke_client_tokens(client_id).await {
            Ok(revoked) => {
                tracing::info!(
                    client_id = %client_id,
                    reason = reason.as_str(),
                    revoked_refresh_tokens = revoked,
                    "revoked refresh tokens after client lifecycle event"
                );
            }
            Err(store_error) => {
                tracing::error!(
                    error = %store_error,
                    client_id = %client_id,
                    reason = reason.as_str(),
                    "failed to revoke refresh tokens after client lifecycle event; \
                     version-invalid token records will remain until expiry"
                );
            }
        }
    }
}

fn map_idempotency_crypto_error(error: ClientIdempotencyError) -> ClientServiceError {
    match error {
        ClientIdempotencyError::UnknownKeyId => ClientServiceError::IdempotencyKeyUnavailable,
        ClientIdempotencyError::InvalidKey => ClientServiceError::IdempotencyKeyInvalid,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefreshTokenCleanupReason {
    SecretRotation,
    ClientDisabled,
}

impl RefreshTokenCleanupReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::SecretRotation => "secret_rotation",
            Self::ClientDisabled => "client_disabled",
        }
    }
}
