//! 同意撤销状态的 Redis 缓存（Issue #64 / #65 / #276）。
//!
//! **职责边界**：
//! PostgreSQL 的 `user_consents.revoked_at` 是撤销事实的唯一权威来源，
//! 本模块只是它前面一层可失效缓存。缓存的作用是**加速拒绝**：命中「已撤销」
//! 时不必回源。它**不负责放行**——放行始终由数据库判定
//! （`ConsentRepository::stored_scopes` 带 `revoked_at IS NULL` 条件），
//! 因此一个陈旧的「已授权」缓存值无法替数据库放行任何请求。
//!
//! **Issue #276：写入交错留下的陈旧撤销标记**
//!
//! 撤销与重新授权都是「先写 PostgreSQL（权威），再写 Redis（缓存）」，两条链路
//! 交错时 Redis 的写入顺序可以与数据库提交顺序相反（时序见
//! [`super::consent_cache_scripts`]）。修复前缓存值是无版本的 `"1"`，迟到的撤销
//! 写入用裸 `SET` 覆盖了重新授权的结论，缓存于是长期声称「已撤销」而数据库里
//! `revoked_at IS NULL`；读路径命中即短路，refresh 和 userinfo 被持续拒绝，
//! 且旧实现的键 TTL 是 180 天——用户重新授权后仍可能数天无法使用该应用。
//!
//! **修复方式（两层，互相独立）**
//!
//! 1. **版本围栏**：缓存值携带产生它的 `state_version`，更新走 Lua 条件写
//!    （[`CONSENT_STATE_UPDATE_SCRIPT`]），缓存中已有更高版本时拒绝落盘。
//!    重新授权写下的 `3:a` 因此能挡住迟到的 `2:r`。这是主修复：Redis 可用时
//!    任何交错顺序都不再产生与数据库矛盾的结论。
//! 2. **有界信任窗口**：键 TTL 从 180 天收到
//!    [`CONSENT_STATE_CACHE_TTL_SECONDS`]。生产模式未命中时回源 PostgreSQL，
//!    缩短 TTL 不削弱撤销效力，只是多一次查询；换来的是任何残余不一致
//!    （重新授权时 Redis 恰好不可用、副本故障转移丢掉新写入）最多存活一个窗口
//!    就自愈，而不是数天。
//!
//! **键前缀更换**：
//! 值格式变了（`"1"` → `"<version>:<state>"`），键前缀同步从 `consent-revoked:`
//! 换成 `consent-state:`。滚动升级期间新代码不读旧键，旧键随自身 TTL 回收；
//! 这比在 Lua 和 Rust 两侧各留一条旧格式分支更简单，代价只是升级瞬间已撤销的
//! 同意会回源一次数据库（结论不变）。

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Script};
use sha2::{Digest, Sha256};

use super::consent_cache_scripts::CONSENT_STATE_UPDATE_SCRIPT;
use super::refresh::REFRESH_TOKEN_ABSOLUTE_TTL_DAYS;
use super::revocation::TokenRevocationError;
use crate::consents::domain::ConsentState;
use crate::consents::repository::{ConsentRepository, PgConsentRepository};
use crate::redis_client::RedisClient;
use crate::users::domain::UserId;

/// 生产模式下同意状态缓存键的 TTL（秒）。
///
/// **取值依据**：
/// - 这是「信任窗口」，不是撤销事实的生命周期。撤销的权威在 PostgreSQL，
///   键到期后下一次判定回源查询 `revoked_at`，结论不变。
/// - 必须显著长于「DB 提交 → Redis 写入」的间隔，版本围栏才能覆盖交错窗口。
///   该间隔的上界是一次 Redis 命令的超时（`REDIS_RESPONSE_TIMEOUT`，5 秒）
///   加上请求内的少量数据库往返，5 分钟留了两个数量级的余量。
/// - 又必须足够短，让任何残余不一致（重新授权时 Redis 不可用、副本故障转移
///   丢掉新写入）在可接受时间内自愈。修复前是 180 天，这正是 Issue #276 中
///   「陈旧标记可留存数天」的直接原因。
/// - 作为拒绝路径的缓存，5 分钟仍能把「已撤销凭据反复重试」压到每对
///   「用户 × Client」每 5 分钟一次数据库查询。
pub const CONSENT_STATE_CACHE_TTL_SECONDS: u64 = 300;

/// 仅缓存模式（无数据库回源）下的 TTL（秒）。
///
/// 该模式没有权威回源，键一到期撤销就失效，因此 TTL 必须覆盖 refresh token
/// 的绝对最大寿命（`REFRESH_TOKEN_ABSOLUTE_TTL_DAYS`）。这也是它
/// **不能用于生产**的原因之一：生产必须用带 `PgConsentRepository` 的构造器。
pub const CONSENT_STATE_CACHE_ONLY_TTL_SECONDS: u64 =
    (REFRESH_TOKEN_ABSOLUTE_TTL_DAYS * 24 * 60 * 60) as u64;

/// 缓存值中的状态标记。
///
/// 单字符而不是 `revoked` / `active` 全词：这个值每次判定都要读一遍，
/// 短标记让 Lua 侧的解析退化为一次 `string.sub`。
const REVOKED_MARKER: &str = "r";
const ACTIVE_MARKER: &str = "a";

/// 缓存中读到的状态结论。
///
/// 只区分两种结论，不带版本号：版本号的唯一用途是 Lua 条件写时的比较，
/// Rust 读路径不需要它。把它留在 Lua 侧避免了「应用读版本、比较、再写」
/// 这种没有原子性的三步操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedConsentState {
    Revoked,
    Active,
}

impl CachedConsentState {
    /// 解析 `"<version>:<state>"`。
    ///
    /// 返回 `None` 表示无法解析，调用方按「未命中」处理（回源数据库）。
    /// 当前不存在这种值；这条分支是为手工写入的脏值或未来格式演进兜底，
    /// 按未命中处理让结论回落到权威源，而不是凭猜测放行或拒绝。
    fn parse(raw: &str) -> Option<Self> {
        let (version, marker) = raw.split_once(':')?;
        version
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)?;
        match marker {
            REVOKED_MARKER => Some(Self::Revoked),
            ACTIVE_MARKER => Some(Self::Active),
            _ => None,
        }
    }
}

/// 同意撤销状态的缓存 + 权威回源。
///
/// 依赖 `PgConsentRepository` 而不是 `ConsentService`：缓存属于基础设施层，
/// 向上依赖应用层会形成反向依赖。这里只需要存储边界的一个读方法。
///
/// `consents` 为 `None` 时是仅缓存模式：没有权威回源，
/// `is_revoked` 只按 Redis 结论返回。该模式仅用于测试，见
/// [`crate::oauth::revocation::TokenRevocationStore::new`]。
#[derive(Clone)]
pub struct ConsentStateCache {
    client: RedisClient,
    consents: Option<PgConsentRepository>,
}

impl ConsentStateCache {
    pub fn new(client: RedisClient, consents: Option<PgConsentRepository>) -> Self {
        Self { client, consents }
    }

    /// 写入「已撤销」缓存结论。
    ///
    /// `version` 必须是产生该结论的那次数据库写入返回的 `state_version`
    /// （`ConsentService::revoke_for_user`）。
    ///
    /// 返回 `false` 表示缓存中已有更高版本，本次写入被条件写拒绝——这正是
    /// Issue #276 要的行为：迟到的撤销写入不能否决数据库已重新授权的状态。
    /// 被拒绝不是错误：权威事实已在数据库，调用方无需补偿。
    pub async fn record_revoked(
        &self,
        user_id: &str,
        client_id: &str,
        version: i64,
    ) -> Result<bool, TokenRevocationError> {
        self.write(user_id, client_id, version, REVOKED_MARKER)
            .await
    }

    /// 写入「已授权」缓存结论（版本围栏）。
    ///
    /// 这个值不用于放行——放行始终由数据库的 `revoked_at IS NULL` 判定。
    /// 它的唯一作用是在缓存里留下「数据库已经走到版本 N 的已授权状态」这一事实，
    /// 让任何版本不高于 N 的迟到撤销写入被条件写拒绝。
    pub async fn record_active(
        &self,
        user_id: &str,
        client_id: &str,
        version: i64,
    ) -> Result<bool, TokenRevocationError> {
        self.write(user_id, client_id, version, ACTIVE_MARKER).await
    }

    /// 按数据库权威状态同步缓存（重新授权与授权码签发路径）。
    ///
    /// 取代旧的「删除缓存键」：删除只是让下一次判定回源，无法阻止一个迟到的
    /// 撤销写入随后落盘。写入带版本的「已授权」围栏才能挡住它。
    ///
    /// 仅缓存模式没有权威可同步，退化为删除键（与旧行为一致）。
    pub async fn refresh_from_database(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        let Some(consents) = &self.consents else {
            return self.forget(user_id, client_id).await;
        };
        let Ok(parsed_user_id) = user_id.parse::<UserId>() else {
            // 不是合法用户标识，不可能存在对应的同意记录
            return Ok(());
        };
        match consents.consent_state(parsed_user_id, client_id).await? {
            Some(state) => {
                self.write_state(user_id, client_id, state).await?;
                Ok(())
            }
            // 没有同意记录时缓存里的任何结论都是错的：没有记录就无法被撤销。
            None => self.forget(user_id, client_id).await,
        }
    }

    /// 判定用户对指定 client 的同意是否已被撤销。
    ///
    /// **判定流程**：
    /// 1. 读缓存。只有「已撤销」结论可以短路返回——缓存只加速拒绝，不放行。
    /// 2. 缓存是「已授权」或未命中时回源数据库（仅缓存模式返回未撤销）。
    /// 3. 回源结论写回缓存（条件写，best-effort）：既回填拒绝结论，
    ///    也顺带续期「已授权」围栏，使活跃授权的围栏随流量持续刷新。
    ///
    /// **fail-secure 取舍**：
    /// - Redis 故障：降级回源，不向调用方报错。缓存不可用不该让认证请求失败。
    /// - 数据库故障：返回 `Err(Database(..))`。调用方（`token_handlers`、
    ///   `userinfo`）已把它映射为 503 temporarily_unavailable，因此既不会放行
    ///   一个可能已撤销的授权，也不会把抖动谎报成 `invalid_grant`。
    pub async fn is_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, TokenRevocationError> {
        let cached = match self.read(user_id, client_id).await {
            Ok(cached) => cached,
            Err(cache_error) => {
                tracing::warn!(
                    error = %cache_error,
                    "consent state cache unavailable, falling back to database"
                );
                None
            }
        };
        // 「已撤销」是确定结论，可以直接短路：写入它的那次条件写已经确认过
        // 缓存中没有更新的状态，且键的 TTL 把信任窗口限制在
        // CONSENT_STATE_CACHE_TTL_SECONDS 内。
        if matches!(cached, Some(CachedConsentState::Revoked)) {
            return Ok(true);
        }

        // 没有权威数据源时（仅缓存模式）只能按缓存结论返回。
        let Some(consents) = &self.consents else {
            return Ok(false);
        };
        let Ok(parsed_user_id) = user_id.parse::<UserId>() else {
            return Ok(false);
        };
        // 回源。缓存里没有「已撤销」有两种可能——从未撤销，或缓存尚未回填 /
        // 已过期，二者无法在 Redis 侧区分，因此必须查权威源。
        let Some(state) = consents.consent_state(parsed_user_id, client_id).await? else {
            // 从未授权：没有可撤销的对象，拦截由 has_scopes 负责。
            return Ok(false);
        };

        self.cache_state_best_effort(user_id, client_id, state)
            .await;
        Ok(state.revoked)
    }

    /// 无条件删除缓存键。
    ///
    /// 不做版本比较：语义是「忘掉缓存」，而不是「写入一个更新的结论」。
    /// 用于仅缓存模式的同步路径，以及测试中模拟 Redis 数据丢失。
    /// 删除本身不会导致错误放行——下一次判定会回源权威库。
    pub async fn forget(&self, user_id: &str, client_id: &str) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(Self::key(user_id, client_id)).await?;
        Ok(())
    }

    /// 缓存键：SHA-256("user:client") 的 URL-safe base64（无填充）。
    ///
    /// 哈希而不是明文拼接：避免 user_id / client_id 出现在 Redis keyspace 中，
    /// 也让键长度固定，与 `sessions::store` 的键约定一致。
    pub(super) fn key(user_id: &str, client_id: &str) -> String {
        let binding = format!("{user_id}:{client_id}");
        let digest = Sha256::digest(binding.as_bytes());
        format!(
            "chenxing:oauth:consent-state:{}",
            URL_SAFE_NO_PAD.encode(digest)
        )
    }

    /// 生效的键 TTL：见两个常量各自的取值依据。
    fn state_ttl(&self) -> u64 {
        if self.consents.is_some() {
            CONSENT_STATE_CACHE_TTL_SECONDS
        } else {
            CONSENT_STATE_CACHE_ONLY_TTL_SECONDS
        }
    }

    async fn read(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<Option<CachedConsentState>, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let raw: Option<String> = connection.get(Self::key(user_id, client_id)).await?;
        Ok(raw.as_deref().and_then(CachedConsentState::parse))
    }

    async fn write_state(
        &self,
        user_id: &str,
        client_id: &str,
        state: ConsentState,
    ) -> Result<bool, TokenRevocationError> {
        let marker = if state.revoked {
            REVOKED_MARKER
        } else {
            ACTIVE_MARKER
        };
        self.write(user_id, client_id, state.version, marker).await
    }

    async fn write(
        &self,
        user_id: &str,
        client_id: &str,
        version: i64,
        marker: &str,
    ) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let accepted: i64 = Script::new(CONSENT_STATE_UPDATE_SCRIPT)
            .key(Self::key(user_id, client_id))
            .arg(version)
            .arg(marker)
            .arg(self.state_ttl())
            .invoke_async(&mut connection)
            .await?;
        if accepted == 0 {
            // 迟到的写入被围栏挡住。这是设计行为而不是故障：数据库已持有更新的
            // 事实，缓存保留更新的结论。记 debug 便于排查交错时序。
            tracing::debug!(
                client_id = %client_id,
                version,
                marker,
                "stale consent state cache write rejected by version fence"
            );
        }
        Ok(accepted == 1)
    }

    /// 回填缓存（best-effort）。
    ///
    /// 写失败只记 warn：数据库已持有权威事实，缓存缺失只会让下次判定再回源一次，
    /// 不影响正确性。
    async fn cache_state_best_effort(&self, user_id: &str, client_id: &str, state: ConsentState) {
        if let Err(cache_error) = self.write_state(user_id, client_id, state).await {
            tracing::warn!(
                error = %cache_error,
                "failed to back-fill consent state cache from database"
            );
        }
    }
}

#[cfg(test)]
#[path = "consent_cache_tests.rs"]
mod tests;
