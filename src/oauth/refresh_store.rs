use redis::{AsyncCommands, Script};
use thiserror::Error;

use super::{
    refresh::{REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, REFRESH_TOKEN_SLIDING_TTL_DAYS, RefreshToken},
    refresh_store_scripts::{
        REMOVE_WITHOUT_TOMBSTONE_SCRIPT, ROTATE_WITH_TOMBSTONE_SCRIPT, SAVE_WITH_INDEXES_SCRIPT,
        TAKE_IF_MATCHES_SCRIPT,
    },
};
use crate::{clock::SharedClock, redis_client::RedisClient};

// 墓碑类型定义在 `refresh_tombstone`，但调用方历来从 `refresh_store` 导入，
// 这里保持那条路径可用。
pub use super::refresh_tombstone::{Tombstone, TombstoneState};

#[path = "refresh_store_revocation.rs"]
mod revocation;
pub use revocation::FamilyRevocation;

/// 绝对生命周期 TTL（从 `refresh.rs` 常量计算，保证单一信源）。
const ABSOLUTE_TTL_SECONDS: u64 = (REFRESH_TOKEN_ABSOLUTE_TTL_DAYS * 24 * 60 * 60) as u64;

/// 墓碑的 TTL（旧 token 被消费后需要保留一段时间以检测重放）。
const TOMBSTONE_TTL_SECONDS: u64 = (REFRESH_TOKEN_SLIDING_TTL_DAYS * 24 * 60 * 60) as u64;

/// 索引 TTL：client / family 索引的过期时间设为绝对上限，防止无界增长。
const INDEX_TTL_SECONDS: u64 = ABSOLUTE_TTL_SECONDS;

/// Client 级撤销单个 Lua 批次的成员上限，避免长时间阻塞 Redis。
const CLIENT_REVOKE_BATCH_SIZE: u64 = 128;

/// Token 主键前缀（保持与历史一致，避免 keyspace 迁移风险）。
const TOKEN_KEY_PREFIX: &str = "chenxing:oauth:refresh:";
/// Client 索引前缀。
const CLIENT_IDX_PREFIX: &str = "cx:refresh:client_idx:";
/// Family 索引前缀（RFC 9700 §4.14.2 撤销单元）。
const FAMILY_IDX_PREFIX: &str = "cx:refresh:family_idx:";
/// 墓碑前缀（用于重放检测）。
const TOMBSTONE_PREFIX: &str = "cx:refresh:tombstone:";
/// Family 级撤销墓志前缀。
///
/// 墓志与 family 索引分开存放：索引在撤销时被删空，而墓志必须在成员消失后
/// 继续存在，用来挡住飞行中的轮换请求把新成员写回已撤销的 family。
const FAMILY_REVOKED_PREFIX: &str = "cx:refresh:family_revoked:";

/// 撤销单元的键集合。
///
/// 旧格式 token 没有 `family_id`。这类 token 不能共用同一个空后缀键——否则
/// 撤销任意一个旧 token 都会给所有旧 token 写上同一个墓志，把它们连坐撤销。
/// 因此为它们按 token 哈希合成一个「单成员 family」：索引集合不存在（撤销时
/// 只有提交的那一个 token 被删），墓志按 token 独立。
///
/// 回退后缀 `legacy-token:{hash}` 与旧格式 token 轮换后继的派生家族
/// （`RefreshToken::family_identifier`，Issue #313）是同一个键空间：从活
/// payload、墓碑还是轮换后继定位，撤销都命中同一撤销域。
pub(super) struct FamilyScope {
    index_key: String,
    revoked_key: String,
}

impl FamilyScope {
    pub(super) fn new(family_id: &str, token_hash: &str) -> Self {
        let discriminator = if family_id.is_empty() {
            format!("legacy-token:{token_hash}")
        } else {
            family_id.to_owned()
        };
        Self {
            index_key: format!("{FAMILY_IDX_PREFIX}{discriminator}"),
            revoked_key: format!("{FAMILY_REVOKED_PREFIX}{discriminator}"),
        }
    }
}

/// 一次轮换尝试的结果。
///
/// 四种结果的处置完全不同，不能压缩成 `bool`：`CasMismatch` 说明键仍在但
/// 值已变，这个 token 必定已被别人消费（Issue #293：这就是重放）；
/// `KeyMissing` 说明键已消失，可能是重放也可能是过期/驱逐/时钟偏差，
/// 必须查墓碑才能区分（Issue #312）；`FamilyRevoked` 说明整个 grant
/// 已经死亡，重试也不会成功。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOutcome {
    /// 轮换成功，新 token 已经可兑换。
    Rotated,
    /// CAS 失败：键仍在，但旧 token 已经不是 Redis 里的当前值。
    CasMismatch,
    /// 旧 token 的键已不存在。歧义结果：可能已被消费（重放），也可能只是
    /// 过期/驱逐/时钟偏差（良性）。调用方必须查墓碑区分，不得直接按重放处置。
    KeyMissing,
    /// 目标 family 已被撤销，拒绝写入任何新成员。
    FamilyRevoked,
}

#[derive(Clone)]
pub struct RefreshTokenStore {
    client: RedisClient,
    clock: SharedClock,
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
            clock: SharedClock::system(),
        }
    }

    /// 注入共享时钟（`AppState` 构造时调用）。
    ///
    /// 墓碑的 `recorded_at` 和主键 TTL 都由它决定，因此固定时钟可以直接驱动
    /// 「并发窗口内」与「replay」的判定边界，无需真实等待。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    // ── 计算 token hash（用于主键与索引成员）─────────────────────────────
    //
    // 与 `revocation.rs` / `sessions::store` 一致使用 SHA-256 + URL-safe base64：
    // 原始 token 值不进入 Redis keyspace，也不进入索引成员，
    // 避免 keyspace dump 或慢查询日志泄露可用凭据。
    fn token_hash(value: &str) -> String {
        super::refresh::refresh_token_hash(value)
    }

    // ── 主键 / 索引键 / 墓碑键的构造 ──────────────────────────────────────
    fn token_key(value: &str) -> String {
        Self::token_key_for_hash(&Self::token_hash(value))
    }

    fn token_key_for_hash(hash: &str) -> String {
        format!("{TOKEN_KEY_PREFIX}{hash}")
    }

    fn client_idx_key(client_id: &str) -> String {
        format!("{CLIENT_IDX_PREFIX}{client_id}")
    }

    fn family_idx_key(family_id: &str) -> String {
        format!("{FAMILY_IDX_PREFIX}{family_id}")
    }

    fn tombstone_key(value: &str) -> String {
        Self::tombstone_key_for_hash(&Self::token_hash(value))
    }

    fn tombstone_key_for_hash(hash: &str) -> String {
        format!("{TOMBSTONE_PREFIX}{hash}")
    }

    /// 计算主键 TTL：`min(滑动窗口剩余, 绝对到期剩余)`，至少 1 秒。
    ///
    /// Issue #109 的核心修复点。旧实现每次轮换都无条件 `SETEX` 30 天，
    /// 只要客户端 30 天内用一次，Redis 侧的有效期就无限向后滑动，
    /// 形成永不过期的凭据。现在 TTL 被绝对截止时间夹住，
    /// 即使持续轮换，Redis 也会在首次签发后 180 天让键自然消失。
    fn effective_ttl(&self, token: &RefreshToken) -> u64 {
        effective_ttl_at(token, self.clock.now())
    }

    // ── 读写操作 ─────────────────────────────────────────────────────────

    /// 保存一个新签发的 Refresh Token。
    ///
    /// 只用于授权码兑换：那里的 family 是刚生成的，不可能处于已撤销状态。
    /// 往既有 family 追加成员的唯一入口是 [`Self::rotate_if_matches`]，
    /// 它会检查 family 撤销墓志。
    pub async fn save(&self, token: &RefreshToken) -> Result<(), RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(token)?;
        let hash = Self::token_hash(&token.value);
        let ttl = self.effective_ttl(token);
        let _: i32 = Script::new(SAVE_WITH_INDEXES_SCRIPT)
            .key(Self::token_key_for_hash(&hash))
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

    pub async fn find(&self, value: &str) -> Result<Option<RefreshToken>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::token_key(value)).await?;
        payload
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(RefreshTokenStoreError::from)
    }

    /// 删除单个 token 并清理索引；不写墓碑，也绝不删除已存在的墓碑。
    ///
    /// 唯一的生产调用方是授权码兑换的补偿路径：那里要销毁一个客户端从未收到的
    /// Refresh Token，它不是被消费的凭据，也不是重放证据。客户端主动撤销走
    /// [`Self::revoke_family_on_explicit_revoke`]，语义是撤销整个 grant。
    ///
    /// 已存在的墓碑（尤其是 `Consumed`）是重放检测的证据：删除它会让同一值的
    /// 再次提交从「重放 → family 撤销」退化成「未知 token → 静默拒绝」，给
    /// 攻击者一次免费重试（Issue #356）。因此本方法对墓碑键零操作，墓碑只按
    /// 自身 TTL 自然过期。
    pub async fn remove(&self, value: &str) -> Result<(), RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        // 先读取 payload 以便清理索引（找不到时幂等成功）
        let key = Self::token_key(value);
        let payload: Option<String> = connection.get(&key).await?;
        if let Some(payload) = payload {
            let token: RefreshToken = serde_json::from_str(&payload)?;
            let hash = Self::token_hash(value);
            let _: i32 = Script::new(REMOVE_WITHOUT_TOMBSTONE_SCRIPT)
                .key(&key)
                .key(Self::client_idx_key(&token.client_id))
                .key(Self::family_idx_key(&token.family_id))
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
            self.clock.now(),
        ))?;
        // CAS 消费、索引清理和墓碑写入在同一个 Lua 脚本内完成，
        // 避免「已删除但墓碑未写」的中间状态漏掉后续重放检测。
        let deleted: i32 = Script::new(TAKE_IF_MATCHES_SCRIPT)
            .key(Self::token_key_for_hash(&hash))
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .key(Self::tombstone_key_for_hash(&hash))
            .arg(expected)
            .arg(&hash)
            .arg(tombstone)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(INDEX_TTL_SECONDS)
            .arg(&token.family_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(deleted == 1)
    }

    /// 原子轮换：CAS 消费旧 token、写入新 token、写旧 token 的消费墓碑。
    ///
    /// 写入前检查目标 family 的撤销墓志。撤销和轮换是并发的，没有这道检查时，
    /// 一个在撤销脚本之后才落地的轮换会把新成员写回已经撤销的 grant，
    /// 让 `/oauth/revoke` 的效果被一次竞态抹掉（Issue #295）。
    pub async fn rotate_if_matches(
        &self,
        value: &str,
        token: &RefreshToken,
        replacement: &RefreshToken,
    ) -> Result<RotationOutcome, RefreshTokenStoreError> {
        self.rotate_if_matches_at(value, token, replacement, self.clock.now())
            .await
    }

    /// 与 [`Self::rotate_if_matches`] 相同的 CAS，但墓碑时刻和新 token TTL
    /// 都由 `now` 派生，避免与刚刚放行该 token 的 grant 检查各读一次时钟
    /// （Issue #366）。
    pub async fn rotate_if_matches_at(
        &self,
        value: &str,
        token: &RefreshToken,
        replacement: &RefreshToken,
        now: time::OffsetDateTime,
    ) -> Result<RotationOutcome, RefreshTokenStoreError> {
        let expected = serde_json::to_string(token)?;
        let replacement_payload = serde_json::to_string(replacement)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let old_hash = Self::token_hash(value);
        let new_hash = Self::token_hash(&replacement.value);
        // 墓碑携带后继 token 的家族而不是旧 payload 里的 family_id：旧格式
        // token 轮换时 payload 里还是空串，而家族已经由旧值派生（rotate_at），
        // 用后继家族才能让墓碑定位到的撤销命中轮换后继（Issue #313）。
        // 新格式轮换两者同族，行为不变。
        let tombstone =
            serde_json::to_string(&Tombstone::for_rotation(token, &replacement.family_id, now))?;
        let new_ttl = effective_ttl_at(replacement, now);
        let target_family = FamilyScope::new(&replacement.family_id, &new_hash);
        let rotated: i32 = Script::new(ROTATE_WITH_TOMBSTONE_SCRIPT)
            .key(Self::token_key_for_hash(&old_hash))
            .key(Self::token_key_for_hash(&new_hash))
            .key(Self::client_idx_key(&token.client_id))
            .key(Self::family_idx_key(&token.family_id))
            .key(Self::family_idx_key(&replacement.family_id))
            .key(Self::tombstone_key_for_hash(&old_hash))
            .key(&target_family.revoked_key)
            .arg(expected)
            .arg(replacement_payload)
            .arg(new_ttl)
            .arg(INDEX_TTL_SECONDS)
            .arg(&old_hash)
            .arg(&new_hash)
            .arg(tombstone)
            .arg(TOMBSTONE_TTL_SECONDS)
            .arg(&token.family_id) // ARGV[9]
            .arg(&replacement.family_id) // ARGV[10]
            .invoke_async(&mut connection)
            .await?;
        Ok(match rotated {
            1 => RotationOutcome::Rotated,
            -1 => RotationOutcome::FamilyRevoked,
            // 键已不存在：可能是已被消费（重放），也可能只是过期/驱逐/时钟
            // 偏差。是否按重放处置由调用方查墓碑决定（Issue #312）。
            2 => RotationOutcome::KeyMissing,
            _ => RotationOutcome::CasMismatch,
        })
    }

    /// 原子回滚一次已提交的轮换：删除新 token 并恢复旧 token。
    ///
    /// 轮换成功之后如果后续步骤失败（例如审计落库失败），必须让客户端手里的
    /// 旧凭据重新可用。分成 `remove(new)` + `save(old)` 两步做不到这件事：
    /// 删除失败时 `save` 仍会执行，family 里就同时存在两个活 token；一个已经
    /// 发不出去（客户端只收到了错误响应），却仍能被兑换（Issue #290）。
    ///
    /// 这里复用轮换脚本做反向 CAS：只有当前活 token 仍是 `issued` 时才换回
    /// `previous`，索引与墓碑在同一次脚本内一致更新。
    ///
    /// 非 `Rotated` 的结果都表示不能复活 `previous`：新 token 已被并发消费、
    /// 已经消失（过期/驱逐），或者整个 family 已经被撤销。此时恢复旧 token
    /// 会让已死的 grant 重新出现可兑换凭据。
    pub async fn rollback_rotation(
        &self,
        issued: &RefreshToken,
        previous: &RefreshToken,
    ) -> Result<RotationOutcome, RefreshTokenStoreError> {
        self.rotate_if_matches(&issued.value, issued, previous)
            .await
    }
}

/// 计算主键 TTL：`min(滑动窗口剩余, 绝对到期剩余)`，至少 1 秒。
///
/// Issue #109 的核心修复点。旧实现每次轮换都无条件 `SETEX` 30 天，
/// 只要客户端 30 天内用一次，Redis 侧的有效期就无限向后滑动，
/// 形成永不过期的凭据。现在 TTL 被绝对截止时间夹住，
/// 即使持续轮换，Redis 也会在首次签发后 180 天让键自然消失。
///
/// 与 [`RefreshTokenStore::effective_ttl`] 的区别只是时间来源：轮换路径需要让
/// 墓碑时刻和新 token 的 TTL 共用同一次时钟读取，所以时间由调用方传入。
fn effective_ttl_at(token: &RefreshToken, now: time::OffsetDateTime) -> u64 {
    let abs_remaining = (token.absolute_deadline() - now).whole_seconds();
    let slide_remaining = (token.expires_at - now).whole_seconds();
    // 已过期的 token 给 1 秒 TTL：让键立刻自然消失，
    // 而不是用 0/负数触发 Redis 的参数错误。
    let ttl = abs_remaining.min(slide_remaining).max(1);
    u64::try_from(ttl).unwrap_or(1)
}

#[cfg(test)]
#[path = "refresh_store_tests.rs"]
mod tests;
