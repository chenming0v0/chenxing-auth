//! 门户「同步」：拉提供方最新快照。
//!
//! access_token 寿命很短（CLtermux-go 为 900 秒），同步不能只拿库里的令牌去
//! GET /account：令牌一过期就永远 401。令牌已过期或被提供方以
//! `invalid_access_token` 拒绝时改走刷新，刷新响应本身带回最新快照。
//! 其余失败如实返回错误，不再用旧快照冒充同步成功。

use time::Duration;
use uuid::Uuid;

use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

use super::ResourceServiceService;
use super::provider_result::{is_account_disabled, is_invalid_access_token};
use crate::resource_services::bundle::TokenBundle;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::snapshot::AccountSnapshot;
use crate::resource_services::store::{LiveSnapshotWrite, Store};
use crate::resource_services::types::{BindingRow, ProviderRow};
use crate::resource_services::views::BindingView;

/// 剩余寿命不足这个窗口就直接刷新，避免令牌在出网途中过期。
const ACCESS_EXPIRY_SKEW: Duration = Duration::seconds(30);

impl ResourceServiceService {
    /// 向提供方拉取最新快照。
    ///
    /// - 令牌已过期 / 提供方返回 `invalid_access_token`：复用刷新流程，返回刷新后的绑定。
    /// - 提供方终态 `account_disabled`：先把 live 快照 `status` 写成 `disabled`
    ///   （不 tombstone，兑换走已有的 `disabled` 分支），再返回错误。
    /// - 网络失败、5xx、解密或协议错误：返回错误，不改令牌包和快照。
    pub async fn sync_binding(
        &self,
        credential: UserSessionCredential,
        binding_id: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let (binding, provider) = self.load_sync_target(credential, binding_id).await?;
        if self.access_token_expired(&binding) {
            return self.refresh_for_sync(credential, &binding, "expired").await;
        }
        let ciphertext = binding
            .token_bundle_ciphertext
            .as_deref()
            .ok_or(ServiceError::ReauthorizationRequired)?;
        let plaintext = self.decrypt_bundle(provider.id, binding.id, ciphertext)?;
        let bundle =
            TokenBundle::parse(plaintext.expose().as_bytes()).map_err(ServiceError::Protocol)?;
        let client = self.provider_client(&provider)?;
        let error = match client.account(&bundle.access_token, &binding.uid).await {
            Ok(snapshot) => {
                return self
                    .persist_synced_snapshot(credential, provider.revision, &binding, snapshot)
                    .await;
            }
            Err(error) => error,
        };
        if is_invalid_access_token(&error) {
            return self
                .refresh_for_sync(credential, &binding, "rejected")
                .await;
        }
        tracing::warn!(
            provider_id = %provider.id,
            binding_id = %binding.id,
            error = %error,
            "resource service account sync failed"
        );
        if is_account_disabled(&error) {
            // 终态没写上就返回这个错误，不能退回旧的 active 成功视图。
            self.record_account_disabled(binding.id).await?;
        }
        Err(ServiceError::from(error))
    }

    async fn load_sync_target(
        &self,
        credential: UserSessionCredential,
        binding_id: Uuid,
    ) -> Result<(BindingRow, ProviderRow), ServiceError> {
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(binding) = Store::lock_binding(&mut tx, binding_id).await? else {
            return Err(ServiceError::BindingNotFound);
        };
        if binding.user_id != credential.user_id || !binding.is_live() {
            return Err(ServiceError::BindingNotFound);
        }
        let Some(provider) = Store::lock_provider(&mut tx, binding.provider_id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        if !provider.enabled {
            return Err(ServiceError::ProviderDisabled);
        }
        tx.commit().await?;
        Ok((binding, provider))
    }

    /// 没记录过期时间按未过期处理，交给提供方的 401 决定是否刷新。
    fn access_token_expired(&self, binding: &BindingRow) -> bool {
        binding
            .access_expires_at
            .is_some_and(|expires_at| expires_at <= self.clock.now() + ACCESS_EXPIRY_SKEW)
    }

    /// 每次同步触发的刷新都是一次新操作，用新的幂等键；刷新自己负责会话、
    /// 行锁、lease 和提供方错误收口。
    async fn refresh_for_sync(
        &self,
        credential: UserSessionCredential,
        binding: &BindingRow,
        reason: &'static str,
    ) -> Result<BindingView, ServiceError> {
        tracing::info!(
            provider_id = %binding.provider_id,
            binding_id = %binding.id,
            reason,
            "resource service sync refreshing access token"
        );
        self.refresh_binding(credential, binding.id, Uuid::new_v4())
            .await
    }

    /// 短事务条件写入本次 GET /account 快照。CAS 失败说明并发刷新/同步已推进，
    /// 返回当前 live 行，不改令牌包。
    async fn persist_synced_snapshot(
        &self,
        credential: UserSessionCredential,
        expected_provider_revision: i64,
        binding: &BindingRow,
        snapshot: AccountSnapshot,
    ) -> Result<BindingView, ServiceError> {
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(persisted) = Store::update_live_snapshot(
            &mut tx,
            LiveSnapshotWrite {
                binding_id: binding.id,
                user_id: credential.user_id,
                expected_generation: binding.generation,
                expected_provider_revision,
                snapshot_json: snapshot.to_value(),
            },
        )
        .await?
        else {
            let current = Store::lock_binding(&mut tx, binding.id).await?;
            return match current {
                Some(row) if row.user_id == credential.user_id && row.is_live() => {
                    tx.commit().await?;
                    Ok(BindingView::from_row(&row))
                }
                _ => Err(ServiceError::BindingNotFound),
            };
        };
        tx.commit().await?;
        Ok(BindingView::from_row(&persisted))
    }
}
