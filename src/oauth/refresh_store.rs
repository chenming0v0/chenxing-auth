use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Script};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    refresh::{REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, REFRESH_TOKEN_SLIDING_TTL_DAYS, RefreshToken},
    refresh_store_scripts::{
        REMOVE_WITHOUT_TOMBSTONE_SCRIPT, REMOVE_WITH_TOMBSTONE_SCRIPT,
        REVOKE_CLIENT_TOKENS_SCRIPT, REVOKE_FAMILY_SCRIPT, ROTATE_WITH_TOMBSTONE_SCRIPT,
        SAVE_WITH_INDEXES_SCRIPT, TAKE_IF_MATCHES_SCRIPT,
    },
};
use crate::redis_client::RedisClient;

/// 绝对生命周期 TTL（从 `refresh.rs` 常量计算，保证单一信源）。
const ABSOLUTE_TTL_SECONDS: u64 = (REFRESH_TOKEN_ABSOLUTE_TTL_DAYS * 24 * 60 * 60) as u64;

/// 墓碑的 TTL（旧 token 被消费后需要保留一段时间以检测重放）。
const TOMBSTONE_TTL_SECONDS: u64 = (REFRESH_TOKEN_SLIDING_TTL_DAYS * 24 * 60 * 60) as u64;

/// CAS 失败时允许并发请求共享一次轮换结果的短窗口。
///
/// 只有已经读到旧 token、随后在这个窗口内输掉 CAS 的请求使用该宽限；
/// 缺失 token 的请求仍按真实 replay 处理，避免攻击者靠反复提交旧凭据
/// 无限延迟 family 撤销。
pub const REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS: i64 = 5;

/// 索引 TTL：client / family 索引的过期时间设为绝对上限，防止无界增长。
const INDEX_TTL_SECONDS: u64 = ABSOLUTE_TTL_SECONDS;

/// Token 主键前缀（保持与历史一致，避免 keyspace 迁移风险）。
const TOKEN_KEY_PREFIX: &str = "chenxing:oauth:refresh:";
/// Client 索引前缀。
const CLIENT_IDX_PREFIX: &str = "cx:refresh:client_idx:";
/// Family 索引前缀（RFC 9700 §4.14.2 撤销单元）。
const FAMILY_IDX_PREFIX: &str = "cx:refresh:family_idx:";
/// 墓碑前缀（用于重放检测）。
const TOMBSTONE_PREFIX: &str = "cx:refresh:tombstone:";

/// 墓碑状态。
///
/// `Consumed` 表示 token 被正常单次消费/轮换，是 replay 检测的候选；
/// `ExplicitRevoke` 表示主动撤销，不应被当成凭据重放；
/// `FamilyRevoked` 表示 family 已经完成撤销，重复提交不应再次执行撤销脚本。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneState {
    #[default]
    Consumed,
    ExplicitRevoke,
    FamilyRevoked,
}

/// 墓碑载荷（存入 Redis，供重放检测时校验 client_id 和消费状态）。
///
/// 墓碑携带 `client_id` 是为了防范跨客户端 DoS：若不校验，
/// Client A 提交 Client B 已过期的 token，就能触发 B 的 family 撤销，
/// 把重放防御变成摧毁合法凭据的工具（Issue #110）。`recorded_at` 只保存
/// Unix 秒级时间戳，不保存 refresh token 原值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub family_id: String,
    pub client_id: String,
    pub user_id: String,
    #[serde(default)]
    pub state: TombstoneState,
    #[serde(default)]
    pub recorded_at: i64,
}

impl Tombstone {
    fn for_token(token: &RefreshToken, state: TombstoneState) -> Self {
        Self {
            family_id: token.family_id.clone(),
            client_id: token.client_id.clone(),
            user_id: token.user_id.clone(),
            state,
            recorded_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    /// 只有近期的正常消费墓碑才能解释 CAS loser 的并发竞争。
    pub fn is_recent_consumption(&self, now: time::OffsetDateTime) -> bool {
        if self.state != TombstoneState::Consumed {
            return false;
        }
        let Some(age) = now.unix_timestamp().checked_sub(self.recorded_at) else {
            return false;
        };
        (0..=REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS).contains(&age)
    }

    pub fn is_replay_candidate(&self) -> bool {
        self.state == TombstoneState::Consumed
    }
}

#[derive(Clone)]
pub struct RefreshTokenStore {
    client: RedisClient,
}

#[derive(Debug, Error)]
pub enum RefreshTokenStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("refresh token serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl RefreshTokenStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
        }
    }

    // ── 计算 token hash（用于主键与索引成员）─────────────────────────────
    //
    // 与 `revocation.rs` / `sessions::store` 一致使用 SHA-256 + URL-safe base64：
    // 原始 token 值不进入 Redis keyspace，也不进入索引成员，
    // 避免 keyspace dump 或慢查询日志泄露可用凭据。
    fn token_hash(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    // ── 主键 / 索引键 / 墓碑键的构造 ──────────────────────────────────────
    fn token_key(value: &str) -> String {
        format!("{TOKEN_KEY_PREFIX}{}", Self::token_hash(value))
    }

    fn client_idx_key(client_id: &str) -> String {
        format!("{CLIENT_IDX_PREFIX}{client_id}")
    }

    fn family_idx_key(family_id: &str) -> String {
        format!("{FAMILY_IDX_PREFIX}{family_id}")
    }

    fn tombstone_key(value: &str) -> String {
        format!("{TOMBSTONE_PREFIX}{}", Self::token_hash(value))
    }

    /// 计算主键 TTL：`min(滑动窗口剩余, 绝对到期剩余)`，至少 1 秒。
    ///
    /// Issue #109 的核心修复点。旧实现每次轮换都无条件 `SETEX` 30 天，
    /// 只要客户端 30 天内用一次，Redis 侧的有效期就无限向后滑动，
    /// 形成永不过期的凭据。现在 TTL 被绝对截止时间夹住，
    /// 即使持续轮换，Redis 也会在首次签发后 180 天让键自然消失。
    fn effective_ttl(token: &RefreshToken) -> u64 {
        let now = time::OffsetDateTime::now_utc();
        let abs_remaining = (token.absolute_deadline() - now).whole_seconds();
        let slide_remaining = (token.expires_at - now).whole_seconds();
        // 已过期的 token 给 1 秒 TTL：让键立刻自然消失，
        // 而不是用 0/负数触发 Redis 的参数错误。
        let ttl = abs_remaining.min(slide_remaining).max(1);
        u64::try_from(ttl).unwrap_or(1)
    }

    // ── 读写操作 ─────────────────────────────────────────────────────────

    pub async fn save(&self, token: &RefreshToken) -> Result<(), RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(token)?;
        let hash = Self::token_hash(&token.value);
        let ttl = Self::effective_ttl(token);
        let _: i32 = Script::new(SAVE_WITH_INDEXES_SCRIPT)
            .key(Self::token_key(&token.value))
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .arg(payload)
            .arg(ttl)
            .arg(INDEX_TTL_SECONDS)
            .arg(&hash)
            .arg(&token.family_id) // 空字符串时 Lua 不写 family 索引
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    pub async fn take(&self, value: &str) -> Result<Option<RefreshToken>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let key = Self::token_key(value);
        let payload: Option<String> = connection.get(&key).await?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let token: RefreshToken = serde_json::from_str(&payload)?;
        let hash = Self::token_hash(value);
        let tombstone = serde_json::to_string(&Tombstone::for_token(
            &token,
            TombstoneState::Consumed,
        ))?;
        let _: i32 = Script::new(REMOVE_WITH_TOMBSTONE_SCRIPT)
            .key(&key)
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .key(Self::tombstone_key(value))
            .arg(&hash)
            .arg(tombstone)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(INDEX_TTL_SECONDS)
            .arg(&token.family_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(Some(token))
    }

    pub async fn find(&self, value: &str) -> Result<Option<RefreshToken>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::token_key(value)).await?;
        payload
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(RefreshTokenStoreError::from)
    }

    pub async fn remove(&self, value: &str) -> Result<(), RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        // 先读取 payload 以便清理索引（找不到时幂等成功）
        let key = Self::token_key(value);
        let payload: Option<String> = connection.get(&key).await?;
        if let Some(payload) = payload {
            let token: RefreshToken = serde_json::from_str(&payload)?;
            let hash = Self::token_hash(value);
            // 主动撤销和补偿删除不写 replay tombstone。否则提交一个已经被
            // 主动撤销的 token 会被误判为重放，进而触发 family DoS。
            let _: i32 = Script::new(REMOVE_WITHOUT_TOMBSTONE_SCRIPT)
                .key(&key)
                .key(Self::client_idx_key(&token.client_id))
                .key(Self::family_idx_key(&token.family_id))
                .key(Self::tombstone_key(value))
                .arg(&hash)
                .arg(INDEX_TTL_SECONDS)
                .arg(&token.family_id)
                .invoke_async(&mut connection)
                .await?;
        }
        Ok(())
    }

    pub async fn take_if_matches(
        &self,
        value: &str,
        token: &RefreshToken,
    ) -> Result<bool, RefreshTokenStoreError> {
        let expected = serde_json::to_string(token)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let hash = Self::token_hash(value);
        let tombstone = serde_json::to_string(&Tombstone::for_token(
            token,
            TombstoneState::Consumed,
        ))?;
        // CAS 消费、索引清理和墓碑写入在同一个 Lua 脚本内完成，
        // 避免「已删除但墓碑未写」的中间状态漏掉后续重放检测。
        let deleted: i32 = Script::new(TAKE_IF_MATCHES_SCRIPT)
            .key(Self::token_key(value))
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .key(Self::tombstone_key(value))
            .arg(expected)
            .arg(hash)
            .arg(tombstone)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(INDEX_TTL_SECONDS)
            .arg(&token.family_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(deleted == 1)
    }

    pub async fn rotate_if_matches(
        &self,
        value: &str,
        token: &RefreshToken,
        replacement: &RefreshToken,
    ) -> Result<bool, RefreshTokenStoreError> {
        let expected = serde_json::to_string(token)?;
        let replacement_payload = serde_json::to_string(replacement)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let old_hash = Self::token_hash(value);
        let new_hash = Self::token_hash(&replacement.value);
        let tombstone = serde_json::to_string(&Tombstone::for_token(
            token,
            TombstoneState::Consumed,
        ))?;
        let new_ttl = Self::effective_ttl(replacement);
        let rotated: i32 = Script::new(ROTATE_WITH_TOMBSTONE_SCRIPT)
            .key(Self::token_key(value))
            .key(Self::token_key(&replacement.value))
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .key(Self::family_idx_key(&replacement.family_id))
            .key(Self::tombstone_key(value))
            .arg(expected)
            .arg(replacement_payload)
            .arg(new_ttl)
            .arg(INDEX_TTL_SECONDS)
            .arg(old_hash)
            .arg(new_hash)
            .arg(tombstone)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(&token.family_id) // ARGV[9]
            .arg(&replacement.family_id) // ARGV[10]
            .invoke_async(&mut connection)
            .await?;
        Ok(rotated == 1)
    }

    // ── 重放检测相关操作（RFC 9700 §4.14.2）──────────────────────────────

    /// 读取墓碑（如果存在）。
    ///
    /// 用于区分「token 不存在因为从未签发」和「token 曾合法存在但已被消费/
    /// 轮换」两种情况。`Consumed` 是重放候选，`FamilyRevoked` 只表示该
    /// family 已经处理过；没有墓碑的未知 token 是普通无效 token。
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

    /// 撤销整个 Token Family（RFC 9700 §4.14.2）。
    ///
    /// 当检测到重放时调用；删除该 family 中所有仍然存活的 token，
    /// 并给每个成员写墓碑，使后续重放依然可被识别和审计。
    ///
    /// 只删除 `token_hash` 满足 `{TOKEN_KEY_PREFIX}{hash}` 格式的键，
    /// 不影响其他 client 的数据。
    ///
    /// 返回被撤销的 token 数量（审计用）。
    pub async fn revoke_family(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
    ) -> Result<u64, RefreshTokenStoreError> {
        self.revoke_family_internal(family_id, client_id, user_id, None)
            .await
    }

    /// 撤销 family，并把触发 replay 的墓碑原子标记为 `family_revoked`。
    ///
    /// `replayed_value` 只用于计算哈希并定位墓碑，不会进入 Redis payload 或日志。
    /// 标记由同一个 Lua 脚本完成，使并发 replay 中只有第一个请求执行 family
    /// 撤销；后续请求只得到普通 invalid_grant。
    pub async fn revoke_family_after_replay(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
        replayed_value: &str,
    ) -> Result<u64, RefreshTokenStoreError> {
        self.revoke_family_internal(
            family_id,
            client_id,
            user_id,
            Some(replayed_value),
        )
        .await
    }

    async fn revoke_family_internal(
        &self,
        family_id: &str,
        client_id: &str,
        user_id: &str,
        replayed_value: Option<&str>,
    ) -> Result<u64, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let tombstone_json = serde_json::to_string(&Tombstone {
            family_id: family_id.to_owned(),
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            state: TombstoneState::FamilyRevoked,
            recorded_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        })?;
        let replayed_hash = replayed_value.map(Self::token_hash).unwrap_or_default();
        let removed: i64 = Script::new(REVOKE_FAMILY_SCRIPT)
            .key(Self::family_idx_key(family_id))
            .key(Self::client_idx_key(client_id))
            .arg(TOKEN_KEY_PREFIX)
            .arg(TOMBSTONE_PREFIX)
            .arg(tombstone_json)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(replayed_hash)
            .invoke_async(&mut connection)
            .await?;
        Ok(removed.max(0) as u64)
    }

    /// 撤销某个 Client 的全部 Refresh Token（Issue #62：Secret 轮换时调用）。
    ///
    /// O(n) 操作，n = 该 Client 存活 token 数。Secret 轮换是低频管理操作，
    /// 成本可接受（Issue #62 设计决策 §6）。
    ///
    /// 故意不写墓碑：Secret 轮换不是凭据泄露信号，旧 token 后续应静默返回
    /// `invalid_grant`，不触发「检测到重放」的审计噪声。
    ///
    /// 返回被撤销的 token 数量。
    pub async fn revoke_client_tokens(
        &self,
        client_id: &str,
    ) -> Result<u64, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let removed: i64 = Script::new(REVOKE_CLIENT_TOKENS_SCRIPT)
            .key(Self::client_idx_key(client_id))
            .arg(TOKEN_KEY_PREFIX)
            .arg(FAMILY_IDX_PREFIX)
            .arg(TOMBSTONE_PREFIX)
            .invoke_async(&mut connection)
            .await?;
        Ok(removed.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::{Tombstone, TombstoneState};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn legacy_tombstones_remain_replay_candidates() {
        let tombstone: Tombstone = serde_json::from_str(
            r#"{"family_id":"family","client_id":"client","user_id":"user"}"#,
        )
        .expect("legacy tombstone should deserialize");

        assert_eq!(tombstone.state, TombstoneState::Consumed);
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        assert!(!tombstone.is_recent_consumption(now));
        assert!(tombstone.is_replay_candidate());
    }
}
