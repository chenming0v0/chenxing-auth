use uuid::Uuid;

use crate::users::domain::UserId;

use super::ResourceServiceService;
use crate::resource_services::bundle::TokenBundle;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::snapshot::AccountSnapshot;
use crate::resource_services::store::{LiveSnapshotWrite, Store};
use crate::resource_services::types::BindingRow;
use crate::resource_services::views::BindingView;

impl ResourceServiceService {
    /// 某用户在某资源服务上的 live 绑定；不解密令牌包，只读行。
    pub async fn live_binding(
        &self,
        provider_id: Uuid,
        user_id: UserId,
    ) -> Result<Option<BindingRow>, ServiceError> {
        Ok(self.store.find_live_binding(provider_id, user_id).await?)
    }

    /// 向提供方拉取最新快照。网络失败时返回本地缓存，不使令牌失效。
    pub async fn sync_binding(
        &self,
        user_id: UserId,
        binding_id: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let binding = self
            .store
            .get_binding(binding_id)
            .await?
            .ok_or(ServiceError::BindingNotFound)?;
        if binding.user_id != user_id || !binding.is_live() {
            return Err(ServiceError::BindingNotFound);
        }
        let Some(provider) = self.store.get_provider(binding.provider_id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        let Some(ciphertext) = binding.token_bundle_ciphertext.as_deref() else {
            return Ok(BindingView::from_row(&binding));
        };
        let plaintext = match self.decrypt_bundle(provider.id, binding.id, ciphertext) {
            Ok(value) => value,
            Err(_) => return Ok(BindingView::from_row(&binding)),
        };
        let bundle = match TokenBundle::parse(plaintext.expose().as_bytes()) {
            Ok(value) => value,
            Err(_) => return Ok(BindingView::from_row(&binding)),
        };
        let client = self.provider_client(&provider)?;
        match client.account(&bundle.access_token, &binding.uid).await {
            Ok(snapshot) => {
                self.persist_synced_snapshot(user_id, provider.revision, &binding, snapshot)
                    .await
            }
            Err(_) => Ok(BindingView::from_row(&binding)),
        }
    }

    /// 短事务条件写入本次 GET /account 快照。CAS 失败不改令牌包。
    async fn persist_synced_snapshot(
        &self,
        user_id: UserId,
        expected_provider_revision: i64,
        binding: &BindingRow,
        snapshot: AccountSnapshot,
    ) -> Result<BindingView, ServiceError> {
        let mut tx = self.pool.begin().await?;
        let Some(persisted) = Store::update_live_snapshot(
            &mut tx,
            LiveSnapshotWrite {
                binding_id: binding.id,
                user_id,
                expected_generation: binding.generation,
                expected_provider_revision,
                snapshot_json: snapshot.to_value(),
            },
        )
        .await?
        else {
            let current = Store::lock_binding(&mut tx, binding.id).await?;
            return match current {
                Some(row) if row.user_id == user_id && row.is_live() => Err(ServiceError::Conflict),
                _ => Err(ServiceError::BindingNotFound),
            };
        };
        tx.commit().await?;
        Ok(BindingView::from_row(&persisted))
    }
}
