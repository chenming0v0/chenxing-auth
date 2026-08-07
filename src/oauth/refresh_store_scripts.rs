//! Refresh Token 存储的 Lua 脚本（RFC 9700 §4.14.2：Token Family 撤销）。
//!
//! 这些脚本在 Redis 内部拼接部分键名（token 主键、family 索引），与
//! `request_store_scripts.rs` 的既有做法一致。因此本项目假定单实例/主从
//! Redis，不支持 Cluster 模式下的跨 slot 访问。
//!
//! 索引成员统一使用 `token_hash` 而不是原始 token 值，避免凭据出现在
//! Redis keyspace 中（与 `sessions::store` 的哈希键约定一致）。

/// 原子保存 Refresh Token 并更新 client / family 索引。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[5]` 为空时不使用）
/// - `ARGV[1]` token JSON
/// - `ARGV[2]` 主键 TTL（秒）
/// - `ARGV[3]` 索引 TTL（秒）
/// - `ARGV[4]` token_hash
/// - `ARGV[5]` family_id，空字符串表示旧格式 token，跳过 family 索引
pub const SAVE_WITH_INDEXES_SCRIPT: &str = r#"
redis.call('SETEX', KEYS[1], ARGV[2], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[3])
if ARGV[5] ~= '' then
    redis.call('SADD', KEYS[3], ARGV[4])
    redis.call('EXPIRE', KEYS[3], ARGV[3])
end
return 1
"#;

/// 原子轮换 Refresh Token：CAS 校验旧值、写入新值、删除旧值、写墓碑。
///
/// 墓碑（tombstone）是重放检测的依据：旧 token 被删除后再次提交时，
/// `find` 返回 `None`，此时通过墓碑才能知道「这是一个已被正常消费的
/// token 被重放」，进而撤销整个 family。
///
/// - `KEYS[1]` 旧 token 主键
/// - `KEYS[2]` 新 token 主键
/// - `KEYS[3]` client 索引键
/// - `KEYS[4]` 旧 family 索引键
/// - `KEYS[5]` 新 family 索引键
/// - `KEYS[6]` 墓碑键
/// - `ARGV[1]` 预期旧 token JSON（CAS 比较值）
/// - `ARGV[2]` 新 token JSON
/// - `ARGV[3]` 新主键 TTL（秒）
/// - `ARGV[4]` 索引 TTL（秒）
/// - `ARGV[5]` 旧 token_hash
/// - `ARGV[6]` 新 token_hash
/// - `ARGV[7]` 墓碑 JSON
/// - `ARGV[8]` 墓碑 TTL（秒）
/// - `ARGV[9]` 旧 family_id，空表示旧格式 token
/// - `ARGV[10]` 新 family_id，空表示不写 family 索引
///
/// 返回 `1` 轮换成功，`0` 表示 CAS 失败（旧 token 已被消费或被并发轮换）。
pub const ROTATE_WITH_TOMBSTONE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then
    return 0
end
redis.call('SETEX', KEYS[2], ARGV[3], ARGV[2])
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[3], ARGV[5])
redis.call('SADD', KEYS[3], ARGV[6])
redis.call('EXPIRE', KEYS[3], ARGV[4])
if ARGV[9] ~= '' then
    redis.call('SREM', KEYS[4], ARGV[5])
    redis.call('EXPIRE', KEYS[4], ARGV[4])
end
if ARGV[10] ~= '' then
    redis.call('SADD', KEYS[5], ARGV[6])
    redis.call('EXPIRE', KEYS[5], ARGV[4])
end
redis.call('SETEX', KEYS[6], ARGV[8], ARGV[7])
return 1
"#;

/// 原子删除单个 token、清理索引并写墓碑。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[5]` 为空时不使用）
/// - `KEYS[4]` 墓碑键
/// - `ARGV[1]` token_hash
/// - `ARGV[2]` 墓碑 JSON
/// - `ARGV[3]` 墓碑 TTL（秒）
/// - `ARGV[4]` 索引 TTL（秒）
/// - `ARGV[5]` family_id，空表示旧格式 token
pub const REMOVE_WITH_TOMBSTONE_SCRIPT: &str = r#"
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[2], ARGV[4])
if ARGV[5] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[1])
    redis.call('EXPIRE', KEYS[3], ARGV[4])
end
redis.call('SETEX', KEYS[4], ARGV[3], ARGV[2])
return 1
"#;

/// 原子删除单个 token 并清理索引，但不写 replay tombstone。
///
/// 显式 `/oauth/revoke` 和审计失败后的补偿使用这个脚本：主动撤销不是
/// replay 证据，不能因为攻击者再次提交同一凭据而触发 family 撤销。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[3]` 为空时不使用）
/// - `KEYS[4]` 旧 replay tombstone（若存在则一并清理）
/// - `ARGV[1]` token_hash
/// - `ARGV[2]` 索引 TTL（秒）
/// - `ARGV[3]` family_id，空表示旧格式 token
pub const REMOVE_WITHOUT_TOMBSTONE_SCRIPT: &str = r#"
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[4])
redis.call('SREM', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[2], ARGV[2])
if ARGV[3] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[1])
    redis.call('EXPIRE', KEYS[3], ARGV[2])
end
return 1
"#;

/// 原子 CAS 删除 token、清理索引并写墓碑（授权码换取路径的单次消费）。
///
/// 与 `REMOVE_WITH_TOMBSTONE_SCRIPT` 的区别是先做 CAS 比较：只有当前值
/// 与预期完全一致时才消费，避免并发请求各自删掉对方刚写入的 token。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[6]` 为空时不使用）
/// - `KEYS[4]` 墓碑键
/// - `ARGV[1]` 预期 token JSON（CAS 比较值）
/// - `ARGV[2]` token_hash
/// - `ARGV[3]` 墓碑 JSON
/// - `ARGV[4]` 墓碑 TTL（秒）
/// - `ARGV[5]` 索引 TTL（秒）
/// - `ARGV[6]` family_id，空表示旧格式 token
///
/// 返回 `1` 消费成功，`0` 表示 CAS 失败。
pub const TAKE_IF_MATCHES_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then
    return 0
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[5])
if ARGV[6] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[2])
    redis.call('EXPIRE', KEYS[3], ARGV[5])
end
redis.call('SETEX', KEYS[4], ARGV[4], ARGV[3])
return 1
"#;

/// 撤销整个 Token Family（RFC 9700 §4.14.2 的重放响应）。
///
/// 逐个删除 family 索引里的 token 主键，同时给每个成员写墓碑，
/// 使后续任何成员的重放依然能被识别并记录审计。
///
/// - `KEYS[1]` family 索引键
/// - `KEYS[2]` client 索引键
/// - `ARGV[1]` token 主键前缀
/// - `ARGV[2]` 墓碑键前缀
/// - `ARGV[3]` 墓碑 JSON
/// - `ARGV[4]` 墓碑 TTL（秒）
/// - `ARGV[5]` 触发 replay 的 token_hash，可为空
///
/// 返回被删除的 token 数量。
pub const REVOKE_FAMILY_SCRIPT: &str = r#"
if ARGV[5] ~= '' then
    local replay_tombstone = redis.call('GET', ARGV[2] .. ARGV[5])
    if replay_tombstone then
        local decoded = cjson.decode(replay_tombstone)
        if decoded['state'] == 'family_revoked' or decoded['state'] == 'explicit_revoke' then
            return 0
        end
    end
end
local members = redis.call('SMEMBERS', KEYS[1])
local removed = 0
for _, token_hash in ipairs(members) do
    if redis.call('DEL', ARGV[1] .. token_hash) == 1 then
        removed = removed + 1
    end
    redis.call('SREM', KEYS[2], token_hash)
    redis.call('SETEX', ARGV[2] .. token_hash, ARGV[4], ARGV[3])
end
redis.call('DEL', KEYS[1])
if ARGV[5] ~= '' then
    redis.call('SETEX', ARGV[2] .. ARGV[5], ARGV[4], ARGV[3])
end
return removed
"#;

/// 撤销某个 Client 的全部 Refresh Token（Issue #62：Secret 轮换后旧 token 必须失效）。
///
/// 每批非破坏地选取最多 128 个 client 索引成员。整批 payload 成功解析且
/// family 索引清理成功后，才删除 token / tombstone，最后从 client 索引
/// 移除成员作为完成确认。任何失败都保留尚未确认的成员，允许修复后重试。
///
/// 这里不写墓碑：Secret 轮换是管理员的主动操作，不是凭据泄露信号，
/// 旧 token 的后续请求应当只是普通的 `invalid_grant`，不应触发
/// 「检测到重放」的审计噪声。
///
/// - `KEYS[1]` client 索引键
/// - `ARGV[1]` token 主键前缀
/// - `ARGV[2]` family 索引键前缀
/// - `ARGV[3]` tombstone 键前缀（清理同 token 的旧 marker）
/// - `ARGV[4]` 请求的批大小（脚本内硬限制为最多 128）
///
/// 返回 `{被删除的 token 数量, client 索引剩余成员数}`。
pub const REVOKE_CLIENT_TOKENS_SCRIPT: &str = r#"
local batch_size = tonumber(ARGV[4])
if not batch_size or batch_size < 1 then
    return redis.error_reply('ERR invalid client revoke batch size')
end
batch_size = math.min(batch_size, 128)
local members = redis.call('SRANDMEMBER', KEYS[1], batch_size)
local tokens = {}

-- Preflight every selected payload before changing any index or token key.
for _, token_hash in ipairs(members) do
    local token_key = ARGV[1] .. token_hash
    local payload = redis.call('GET', token_key)
    local family_id = nil
    if payload then
        local decoded = cjson.decode(payload)
        if type(decoded) ~= 'table' then
            return redis.error_reply('ERR invalid refresh token payload')
        end
        family_id = decoded['family_id']
        if family_id and type(family_id) ~= 'string' then
            return redis.error_reply('ERR invalid refresh token family_id')
        end
    end
    tokens[#tokens + 1] = {
        hash = token_hash,
        key = token_key,
        family_id = family_id
    }
end

-- A family index error must happen before any selected token is destroyed.
for _, token in ipairs(tokens) do
    if token.family_id and token.family_id ~= '' then
        redis.call('SREM', ARGV[2] .. token.family_id, token.hash)
    end
end

local removed = 0
for _, token in ipairs(tokens) do
    if redis.call('DEL', token.key) == 1 then
        removed = removed + 1
    end
    redis.call('DEL', ARGV[3] .. token.hash)
end

-- Removing the client member is the completion acknowledgement for retries.
for _, token in ipairs(tokens) do
    redis.call('SREM', KEYS[1], token.hash)
end

return {removed, redis.call('SCARD', KEYS[1])}
"#;
