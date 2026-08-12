//! Refresh Token 的撤销操作：family 撤销与 Client 级撤销。
//!
//! 拆成独立文件是因为撤销的语义约束（原子性、幂等性、与轮换的竞态）需要
//! 大量说明，混在存储读写里会让 `refresh_store.rs` 越过源文件长度门槛。
//!
//! 这里是 `RefreshTokenStore` 的 inherent impl 的一部分：作为子模块，它能
//! 访问父模块的私有键构造函数，无需把内部键格式提升为 crate 可见。

use redis::{AsyncCommands, Script};

use super::{
    CLIENT_REVOKE_BATCH_SIZE, FAMILY_IDX_PREFIX, FamilyScope, INDEX_TTL_SECONDS, RefreshTokenStore,
    RefreshTokenStoreError, TOKEN_KEY_PREFIX, TOMBSTONE_PREFIX, TOMBSTONE_TTL_SECONDS, Tombstone,
    TombstoneState,
};
use crate::oauth::refresh_store_scripts::{REVOKE_CLIENT_TOKENS_SCRIPT, REVOKE_FAMILY_SCRIPT};

/// 一次 family 撤销的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyRevocation {
    /// 本次调用真正删除的 token 数量。
    pub revoked_tokens: u64,
    /// 该 family 此前就已经被撤销过，本次没有执行任何删除。
    ///
    /// 并发重放中只有第一个请求得到 `false`，因此「检测到重放」的审计事件
    /// 不会被同一次攻击刷成多条。
    pub already_revoked: bool,
}

impl RefreshTokenStore {
    /// 读取墓碑（如果存在）。
    ///
    /// 用于区分「token 不存在因为从未签发」和「token 曾合法存在但已被消费/
    /// 撤销」两种情况。`Consumed` 是重放证据，`ExplicitRevoke` /
    /// `FamilyRevoked` 只表示凭据已死。
    pub async fn read_tombstone(
        &self,
        value: &str,
    ) -> Result<Option<Tombstone>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::tombstone_key(value)).await?;
        payload
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(RefreshTokenStoreError::from)
    }

    /// 检测到重放后撤销整个 Token Family（RFC 9700 §4.14.2）。
    ///
    /// `replayed_value` 只用于计算哈希以定位主键和墓碑，不进入 Redis payload
    /// 或日志。调用方必须已经确认 `client_id` 与凭据的归属一致，否则任何
    /// Client 都能提交别人的旧 token 来摧毁对方的 grant（Issue #110）。
    pub async fn revoke_family_after_replay(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
        replayed_value: &str,
    ) -> Result<FamilyRevocation, RefreshTokenStoreError> {
        self.revoke_family(
            family_id,
            client_id,
            user_id,
            replayed_value,
            TombstoneState::FamilyRevoked,
        )
        .await
    }

    /// 客户端显式 `/oauth/revoke` 的撤销单元（Issue #295）。
    ///
    /// 撤销的对象是 grant，不是被提交的那一个 token。只删单个 token 会留下
    /// 两个漏洞：轮换后继续存活的兄弟 token 仍然可兑换；以及撤销请求与一次
    /// 飞行中的轮换竞争时，撤销可能落在旧 token 上而新 token 安然无恙。
    ///
    /// 墓碑状态是 `ExplicitRevoke` 而不是 `Consumed`：主动撤销不是凭据泄露
    /// 信号，后续提交同一个值只应得到普通的 `invalid_grant`，不该被记成
    /// 「检测到重放」的安全事件。
    pub async fn revoke_family_on_explicit_revoke(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
        revoked_value: &str,
    ) -> Result<FamilyRevocation, RefreshTokenStoreError> {
        self.revoke_family(
            family_id,
            client_id,
            user_id,
            revoked_value,
            TombstoneState::ExplicitRevoke,
        )
        .await
    }

    /// 撤销 family 的共同实现。
    ///
    /// 成员删除、成员墓碑、提交 token 的删除与墓碑、family 撤销墓志全部在
    /// 一个 Lua 脚本内完成。分步执行会留下「索引已清空但墓志未写」的中间
    /// 状态，此时一次并发轮换就能把新成员写回本该已死的 family。
    async fn revoke_family(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
        submitted_value: &str,
        state: TombstoneState,
    ) -> Result<FamilyRevocation, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let tombstone_json =
            serde_json::to_string(&Tombstone::for_family(family_id, client_id, user_id, state))?;
        let submitted_hash = Self::token_hash(submitted_value);
        let scope = FamilyScope::new(family_id, &submitted_hash);
        let removed: i64 = Script::new(REVOKE_FAMILY_SCRIPT)
            .key(&scope.index_key)
            .key(Self::client_idx_key(client_id))
            .key(&scope.revoked_key)
            .key(Self::token_key_for_hash(&submitted_hash))
            .key(Self::tombstone_key_for_hash(&submitted_hash))
            .arg(TOKEN_KEY_PREFIX)
            .arg(TOMBSTONE_PREFIX)
            .arg(tombstone_json)
            .arg(TOMBSTONE_TTL_SECONDS)
            // 墓志必须比任何成员活得久，否则它过期之后一次迟到的轮换又能写回
            // 这个 family。索引 TTL 就是 family 的绝对生命周期上限。
            .arg(INDEX_TTL_SECONDS)
            .arg(&submitted_hash)
            .invoke_async(&mut connection)
            .await?;
        Ok(if removed < 0 {
            FamilyRevocation {
                revoked_tokens: 0,
                already_revoked: true,
            }
        } else {
            FamilyRevocation {
                revoked_tokens: removed as u64,
                already_revoked: false,
            }
        })
    }

    /// 撤销某个 Client 的全部 Refresh Token（Issue #62：Secret 轮换时调用）。
    ///
    /// 每个 Lua 批次最多处理 128 个索引成员，并重复到 client 索引清空。
    /// payload 解析或 family 索引清理失败时，脚本不会确认对应的 client
    /// 成员，调用方修复数据后可再次执行撤销。
    ///
    /// 故意不写墓碑也不写 family 墓志：Secret 轮换不是凭据泄露信号，旧 token
    /// 后续应静默返回 `invalid_grant`，不触发「检测到重放」的审计噪声。撤销
    /// 按 client 索引进行，同一 family 的成员必然共享 client_id，因此索引被
    /// 清空即等于所有相关 family 都已排空，不存在需要墓志挡住的残留成员。
    ///
    /// 返回被撤销的 token 数量。
    pub async fn revoke_client_tokens(
        &self,
        client_id: &str,
    ) -> Result<u64, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let client_idx_key = Self::client_idx_key(client_id);
        let mut removed = 0_u64;

        loop {
            let (batch_removed, remaining): (i64, i64) = Script::new(REVOKE_CLIENT_TOKENS_SCRIPT)
                .key(&client_idx_key)
                .arg(TOKEN_KEY_PREFIX)
                .arg(FAMILY_IDX_PREFIX)
                .arg(TOMBSTONE_PREFIX)
                .arg(CLIENT_REVOKE_BATCH_SIZE)
                .invoke_async(&mut connection)
                .await?;
            removed = removed.saturating_add(batch_removed.max(0) as u64);
            if remaining <= 0 {
                return Ok(removed);
            }
        }
    }
}
