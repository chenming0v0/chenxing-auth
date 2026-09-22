use serde_json::{Value, json};
use uuid::Uuid;

use crate::users::domain::UserId;
use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

use super::ResourceServiceService;
use super::provider_result::is_account_disabled;
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

    /// 向提供方拉取最新快照。网络失败、5xx、解密失败或并发 CAS 未命中时返回当前
    /// live 行，不使令牌失效。
    ///
    /// 提供方终态 `account_disabled` 例外：先把 live 快照 `status` 写成 `disabled`，再返回错误。
    /// 不 tombstone，否则兑换会当成未绑定，而不是已有的 `disabled` 分支。
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
            Err(error) if is_account_disabled(&error) => {
                self.record_account_disabled(binding.id).await?;
                Err(ServiceError::from(error))
            }
            Err(_) => Ok(BindingView::from_row(&binding)),
        }
    }

    /// 提供方 `account_disabled` 终态。短事务里只改仍 live 的快照 `status`。
    ///
    /// 不复用成功同步的会话门槛：出网期间门户会话失效也不能丢掉这次写入。
    /// 行已不存在或已 tombstone 时不插入、不复活。条件与 `update_live_snapshot`
    /// 相同。generation 取绑定行锁内的当前值，避免出网前的旧值把终态写丢；
    /// provider revision 在同一事务里不加锁读取，避免持有绑定锁时再锁提供方。
    pub(super) async fn record_account_disabled(
        &self,
        binding_id: Uuid,
    ) -> Result<(), ServiceError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = Store::lock_binding(&mut tx, binding_id).await? else {
            tx.commit().await?;
            return Ok(());
        };
        if !row.is_live() {
            tx.commit().await?;
            return Ok(());
        }
        let Some(expected_provider_revision) =
            Store::provider_revision(&mut tx, row.provider_id).await?
        else {
            tx.commit().await?;
            return Ok(());
        };
        let user_id = row.user_id;
        let expected_generation = row.generation;
        let updated = Store::update_live_snapshot(
            &mut tx,
            LiveSnapshotWrite {
                binding_id,
                user_id,
                expected_generation,
                expected_provider_revision,
                snapshot_json: snapshot_marked_disabled(row.snapshot_json),
            },
        )
        .await?;
        if updated.is_none() {
            tracing::warn!(
                binding_id = %binding_id,
                "account_disabled did not update a live binding snapshot"
            );
        }
        tx.commit().await?;
        Ok(())
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

/// 只改 `status`。其余快照字段留着，兑换只看这一列。
fn snapshot_marked_disabled(mut snapshot: Value) -> Value {
    match snapshot.as_object_mut() {
        Some(object) => {
            object.insert("status".to_owned(), json!("disabled"));
            snapshot
        }
        None => json!({ "status": "disabled" }),
    }
}

#[cfg(test)]
mod tests {
    use super::snapshot_marked_disabled;
    use serde_json::json;

    #[test]
    fn disabled_mark_replaces_only_status() {
        let snapshot = snapshot_marked_disabled(json!({
            "status": "active",
            "account": "acct-1",
            "uid": "acct-1"
        }));
        assert_eq!(snapshot["status"], "disabled");
        assert_eq!(snapshot["account"], "acct-1");
        assert_eq!(snapshot["uid"], "acct-1");
    }

    #[test]
    fn disabled_mark_fills_an_empty_object_and_replaces_a_non_object() {
        assert_eq!(
            snapshot_marked_disabled(json!({})),
            json!({ "status": "disabled" })
        );
        assert_eq!(
            snapshot_marked_disabled(json!("nope")),
            json!({ "status": "disabled" })
        );
    }
}
