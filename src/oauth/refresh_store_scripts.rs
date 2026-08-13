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
/// 写入前先检查目标 family 的撤销墓志（`KEYS[7]`）。撤销与轮换是并发的：
/// 撤销脚本按 family 索引清空成员之后，一个还在飞行中的轮换请求可能紧接着
/// 把新成员写回同一个 family，让「已撤销」的 grant 重新拥有可兑换凭据。
/// 墓志的生命周期覆盖 family 的绝对上限，因此这个检查是该竞态的收口点。
///
/// - `KEYS[1]` 旧 token 主键
/// - `KEYS[2]` 新 token 主键
/// - `KEYS[3]` client 索引键
/// - `KEYS[4]` 旧 family 索引键
/// - `KEYS[5]` 新 family 索引键
/// - `KEYS[6]` 墓碑键
/// - `KEYS[7]` 新 family 的撤销墓志键
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
/// 返回 `1` 轮换成功，`0` 表示 CAS 失败（键仍在但值已变：旧 token 已被并发
/// 消费，必定是重放），`-1` 表示目标 family 已被撤销，不允许再写入任何成员。
///
/// `2` 表示旧 token 键已不存在（Issue #312）。这是歧义结果：可能是已被消费
/// （重放），也可能是滑动/绝对期限边界过期、Redis 驱逐或应用与 Redis 时钟
/// 偏差（良性）。脚本无法区分，调用方必须读取墓碑：存在 `Consumed` 墓碑才是
/// 重放并撤销 family；没有墓碑则只是键消失，绝不能撤销整个 grant。
pub const ROTATE_WITH_TOMBSTONE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[7]) == 1 then
    return -1
end
local current = redis.call('GET', KEYS[1])
if current == false then
    return 2
end
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

/// 原子删除单个 token 并清理索引，不写也不删任何 tombstone。
///
/// 唯一的生产调用方是授权码兑换的补偿路径：销毁一个客户端从未收到的 token。
/// 该 token 不可能有墓碑；但脚本必须在结构上保证任何未来调用方都无法抹掉
/// 重放证据——若对「已被消费/撤销过」的 token 执行本脚本，已存在的 `Consumed`
/// 墓碑是重放检测的依据，删除它会让同一值的再次提交从「重放 → family 撤销」
/// 退化成「未知 token → 静默拒绝」，给攻击者一次免费重试（Issue #356）。
/// 因此脚本绝不触碰墓碑键，墓碑只按自身 TTL 自然过期。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[3]` 为空时不使用）
/// - `ARGV[1]` token_hash
/// - `ARGV[2]` 索引 TTL（秒）
/// - `ARGV[3]` family_id，空表示旧格式 token
pub const REMOVE_WITHOUT_TOMBSTONE_SCRIPT: &str = r#"
redis.call('DEL', KEYS[1])
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
/// 这是唯一会写 `Consumed` 墓碑的删除脚本。先做 CAS 比较：只有当前值
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

/// 原子撤销整个 Token Family（RFC 9700 §4.14.2 的重放响应，以及显式
/// `/oauth/revoke` 的撤销单元）。
///
/// 三件事在同一次脚本内完成，缺一不可：
///
/// 1. 删除 family 索引里的每个成员并给它写墓碑，让后续任意成员的提交都能被
///    识别为「已撤销」而不是未知 token。
/// 2. 删除调用方提交的那个 token 主键。它可能已经不在索引里（replay 的旧
///    token），也可能正是唯一的活成员（显式撤销）。
/// 3. 写下 family 级撤销墓志（`KEYS[3]`）。它既是幂等标记，也是轮换脚本的
///    准入检查依据：撤销之后任何飞行中的轮换都无法再往这个 family 写入成员。
///
/// 墓志存在即代表该 family 已经被清空过，此时直接返回 `-1`，不再重复执行
/// 撤销与审计。并发 replay 因此只有第一个请求触发「检测到重放」。
///
/// - `KEYS[1]` family 索引键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 撤销墓志键
/// - `KEYS[4]` 调用方提交的 token 主键
/// - `KEYS[5]` 调用方提交的 token 墓碑键
/// - `ARGV[1]` token 主键前缀
/// - `ARGV[2]` 墓碑键前缀
/// - `ARGV[3]` 墓碑 JSON（`family_revoked` 或 `explicit_revoke`）
/// - `ARGV[4]` 墓碑 TTL（秒）
/// - `ARGV[5]` 墓志 TTL（秒），必须覆盖 family 的绝对生命周期上限
/// - `ARGV[6]` 调用方提交的 token_hash
///
/// 返回被删除的 token 数量，或 `-1` 表示该 family 此前已被撤销。
pub const REVOKE_FAMILY_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[3]) == 1 then
    return -1
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
if redis.call('DEL', KEYS[4]) == 1 then
    removed = removed + 1
end
redis.call('SREM', KEYS[2], ARGV[6])
redis.call('SETEX', KEYS[5], ARGV[4], ARGV[3])
redis.call('SETEX', KEYS[3], ARGV[5], ARGV[3])
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
/// 「检测到重放」的审计噪声。迟到的旧版本写入由 PostgreSQL 签发栅栏阻断，
/// Refresh Token 自身的 `client_secret_version` 是撤销失败时的兑换兜底（#310）。
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
