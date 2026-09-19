use uuid::Uuid;

use crate::users::domain::UserId;
use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

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

    /// 向提供方拉取最新快照。网络失败或并发 CAS 未命中时返回当前 live 行，不使令牌失效。
    pub async fn sync_binding(
        &self,
        credential: UserSessionCredential,
        binding_id: Uuid,
    ) -> Result<BindingView, ServiceError> {
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
        tx.commit().await?;
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
                self.persist_synced_snapshot(credential, provider.revision, &binding, snapshot)
                    .await
            }
            Err(_) => Ok(BindingView::from_row(&binding)),
        }
    }

    /// 短事务条件写入本次 GET /account 快照。CAS 失败不改令牌包，返回当前 live 行。
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
