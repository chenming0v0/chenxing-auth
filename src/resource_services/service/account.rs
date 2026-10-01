use serde_json::{Value, json};
use uuid::Uuid;

use crate::users::domain::UserId;

use super::ResourceServiceService;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::store::{LiveSnapshotWrite, Store};
use crate::resource_services::types::BindingRow;

impl ResourceServiceService {
    /// 某用户在某资源服务上的 live 绑定；不解密令牌包，只读行。
    pub async fn live_binding(
        &self,
        provider_id: Uuid,
        user_id: UserId,
    ) -> Result<Option<BindingRow>, ServiceError> {
        Ok(self.store.find_live_binding(provider_id, user_id).await?)
    }

    /// 提供方 `account_disabled` 终态。短事务里只改仍 live 的快照 `status`。
    ///
    /// 不复用成功同步的会话门槛：出网期间门户会话失效也不能丢掉这次写入。
    /// 行已不存在或已 tombstone 时不插入、不复活。条件与 `update_live_snapshot`
    /// 相同。generation 取绑定行锁内的当前值；provider revision 不加锁读取，
    /// 读和条件更新之间被并发推进时再读一次重写。两次都未命中且行仍 live 则
    /// 回滚并返回错误，不把没写上的终态当成成功。不锁提供方行。
    pub(super) async fn record_account_disabled(
        &self,
        binding_id: Uuid,
    ) -> Result<(), ServiceError> {
        self.write_disabled_snapshot(binding_id, &mut || async {})
            .await
    }

    /// 测试缝：`before_each_update` 在每次条件更新前运行，用来把 provider revision 往前推。
    pub async fn record_account_disabled_with_probe<F, Fut>(
        &self,
        binding_id: Uuid,
        before_each_update: &mut F,
    ) -> Result<(), ServiceError>
    where
        F: FnMut() -> Fut,
        F: Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        self.write_disabled_snapshot(binding_id, before_each_update)
            .await
    }

    async fn write_disabled_snapshot<F, Fut>(
        &self,
        binding_id: Uuid,
        before_each_update: &mut F,
    ) -> Result<(), ServiceError>
    where
        F: FnMut() -> Fut,
        F: Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let mut tx = self.pool.begin().await?;
        let Some(row) = Store::lock_binding(&mut tx, binding_id).await? else {
            tx.commit().await?;
            return Ok(());
        };
        if !row.is_live() {
            tx.commit().await?;
            return Ok(());
        }
        let Some(mut revision) = Store::provider_revision(&mut tx, row.provider_id).await? else {
            tx.commit().await?;
            return Ok(());
        };
        let user_id = row.user_id;
        let expected_generation = row.generation;
        let provider_id = row.provider_id;
        let snapshot_json = snapshot_marked_disabled(row.snapshot_json);

        before_each_update().await;
        let first = Store::update_live_snapshot(
            &mut tx,
            LiveSnapshotWrite {
                binding_id,
                user_id,
                expected_generation,
                expected_provider_revision: revision,
                snapshot_json: snapshot_json.clone(),
            },
        )
        .await?;
        if first.is_some() {
            tx.commit().await?;
            return Ok(());
        }

        // 绑定行锁钉不住提供方 revision。第一次未命中就重读再写一次。
        let Some(next_revision) = Store::provider_revision(&mut tx, provider_id).await? else {
            tx.commit().await?;
            return Ok(());
        };
        revision = next_revision;
        before_each_update().await;
        let second = Store::update_live_snapshot(
            &mut tx,
            LiveSnapshotWrite {
                binding_id,
                user_id,
                expected_generation,
                expected_provider_revision: revision,
                snapshot_json,
            },
        )
        .await?;
        if second.is_some() {
            tx.commit().await?;
            return Ok(());
        }

        let still_live = Store::lock_binding(&mut tx, binding_id)
            .await?
            .is_some_and(|locked| locked.is_live());
        tx.rollback().await?;
        if still_live {
            tracing::warn!(
                binding_id = %binding_id,
                "account_disabled snapshot write missed a live binding"
            );
            return Err(ServiceError::Conflict);
        }
        Ok(())
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
