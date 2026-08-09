//! 同意状态缓存的 Lua 脚本（Issue #276：版本化条件写）。
//!
//! **为什么必须是 Lua 而不是 `SET` / `DEL`**：
//! 撤销和重新授权各自「先写 PostgreSQL，再写 Redis」。两条链路交错时，
//! Redis 的写入顺序可以与数据库的提交顺序相反：
//!
//! ```text
//! 撤销      : UPDATE revoked_at = now()   (DB v2, 已撤销)
//! 重新授权  : UPSERT revoked_at = NULL    (DB v3, 已授权)
//! 重新授权  : 写缓存 a:3
//! 撤销      : 写缓存 r:2                   ← 迟到的写入
//! ```
//!
//! 用裸 `SET` 时最后一步会赢，留下与 `revoked_at IS NULL` 相矛盾的「已撤销」标记，
//! 读路径命中即短路拒绝 refresh / userinfo。用裸 `GET` + 比较 + `SET` 也不行：
//! 三步之间没有原子性，两个并发写入仍可能互相覆盖。
//!
//! 把「读当前版本、比较、写入」收进一个脚本后，Redis 单线程执行保证这三步原子，
//! 迟到写入必然看到更高的版本号并被拒绝。
//!
//! **缓存值格式**：`<state_version>:<state>`，`state` 为 `r`（已撤销）或
//! `a`（已授权）。版本号是 `user_consents.state_version`，由数据库在撤销 /
//! 重新授权的同一条语句内自增。

/// 版本化条件写：仅当缓存中不存在更高版本时才落盘。
///
/// - `KEYS[1]` 同意状态缓存键
/// - `ARGV[1]` 本次要写入的 `state_version`（十进制整数字符串）
/// - `ARGV[2]` 本次要写入的状态标记（`r` 或 `a`）
/// - `ARGV[3]` TTL（秒）
///
/// 返回 `1` 表示已写入，`0` 表示因缓存中已有更高版本而拒绝。
///
/// **为什么版本相等也允许写入**：
/// 版本号在每次状态跃迁时自增，因此相同版本号必然描述相同状态。允许覆盖
/// 使「读路径回填」能顺带续期 TTL，且不会改变结论。
///
/// **无法解析的既有值**：
/// 直接覆盖。当前不存在这种值（Issue #276 同时更换了键前缀，旧格式的
/// `consent-revoked:` 键不再被读写），这里只是让脚本对手工写入的脏值收敛，
/// 而不是把「拒绝写入」留成一个永久卡住缓存的状态。
pub const CONSENT_STATE_UPDATE_SCRIPT: &str = r#"
local incoming_version = tonumber(ARGV[1])
if not incoming_version then
    return redis.error_reply('consent state version must be numeric')
end
local current = redis.call('GET', KEYS[1])
if current then
    local separator = string.find(current, ':', 1, true)
    if separator then
        local cached_version = tonumber(string.sub(current, 1, separator - 1))
        if cached_version and cached_version > incoming_version then
            return 0
        end
    end
end
redis.call('SETEX', KEYS[1], ARGV[3], incoming_version .. ':' .. ARGV[2])
return 1
"#;
