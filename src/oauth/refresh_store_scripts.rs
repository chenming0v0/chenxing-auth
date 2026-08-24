//! Refresh Token 存储的 Lua 脚本（RFC 9700 §4.14.2：Token Family 撤销）。
//!
//! 这些脚本在 Redis 内部拼接部分键名（token 主键、family 索引），与
//! `request_store_scripts.rs` 的既有做法一致。因此本项目假定单实例/主从
//! Redis，不支持 Cluster 模式下的跨 slot 访问。
//!
//! 索引成员统一使用 `token_hash` 而不是原始 token 值，避免凭据出现在
//! Redis keyspace 中（与 `sessions::store` 的哈希键约定一致）。

/// 原子保存 Refresh Token 并更新 client / grant / family 索引。
///
/// grant 索引（`KEYS[4]`，键为 `{user_id}:{client_id}`）是用户「断开应用」的
/// 撤销单元。此前只有 client 维度索引，按 (user, client) 撤销必须扫描该
/// Client 全部用户的 token 才能筛出目标；而用户撤销授权是逐 grant 发生的，
/// 索引就该按 grant 建（Issue #418）。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[5]` 为空时不使用）
/// - `KEYS[4]` grant 索引键（user + client）
/// - `KEYS[5]` token 到 family 的定位键
/// - `ARGV[1]` token JSON
/// - `ARGV[2]` 主键 TTL（秒）
/// - `ARGV[3]` 索引 TTL（秒）
/// - `ARGV[4]` token_hash
/// - `ARGV[5]` family_id，空字符串表示旧格式 token，跳过 family 索引
/// - `ARGV[6]` resolved family_id，用于 token 定位键
pub const SAVE_WITH_INDEXES_SCRIPT: &str = r#"
redis.call('SETEX', KEYS[1], ARGV[2], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[3])
redis.call('SADD', KEYS[4], ARGV[4])
redis.call('EXPIRE', KEYS[4], ARGV[3])
redis.call('SETEX', KEYS[5], ARGV[3], ARGV[6])
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
/// - `KEYS[8]` grant 索引键（user + client；轮换前后同一个 grant）
/// - `KEYS[9]` 旧 token 到 family 的定位键
/// - `KEYS[10]` 新 token 到 family 的定位键
/// - `ARGV[1]` 预期旧 token JSON（只比较 `value` + `cas_revision`）
/// - `ARGV[2]` 新 token JSON
/// - `ARGV[3]` 新主键 TTL（秒）
/// - `ARGV[4]` 索引 TTL（秒）
/// - `ARGV[5]` 旧 token_hash
/// - `ARGV[6]` 新 token_hash
/// - `ARGV[7]` 墓碑 JSON
/// - `ARGV[8]` 墓碑 TTL（秒）
/// - `ARGV[9]` 旧 family_id，空表示旧格式 token
/// - `ARGV[10]` 新 family_id，空表示不写 family 索引
/// - `ARGV[11]` resolved 新 family_id，用于 token 定位键
///
/// 返回 `1` 轮换成功，`0` 表示 CAS 失败（键仍在但值已变：旧 token 已被并发
/// 消费，必定是重放），`-1` 表示目标 family 已被撤销，不允许再写入任何成员。
///
/// `2` 表示旧 token 键已不存在（Issue #312）。这是歧义结果：可能是已被消费
/// （重放），也可能是滑动/绝对期限边界过期、Redis 驱逐或应用与 Redis 时钟
/// 偏差（良性）。脚本无法区分，调用方必须读取墓碑：存在 `Consumed` 墓碑才是
/// 重放并撤销 family；没有墓碑则只是键消失，绝不能撤销整个 grant。
pub const ROTATE_WITH_TOMBSTONE_SCRIPT: &str = concat!(
    super::cas::cas_identity_lua!(),
    r#"
if redis.call('EXISTS', KEYS[7]) == 1 then
    return -1
end
local current = redis.call('GET', KEYS[1])
if current == false then
    return 2
end
if not same_cas_identity(current, ARGV[1], 'value') then
    return 0
end
redis.call('SETEX', KEYS[2], ARGV[3], ARGV[2])
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[3], ARGV[5])
redis.call('SADD', KEYS[3], ARGV[6])
redis.call('EXPIRE', KEYS[3], ARGV[4])
redis.call('SREM', KEYS[8], ARGV[5])
redis.call('SADD', KEYS[8], ARGV[6])
redis.call('EXPIRE', KEYS[8], ARGV[4])
redis.call('DEL', KEYS[9])
redis.call('SETEX', KEYS[10], ARGV[4], ARGV[11])
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
"#
);

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
/// - `KEYS[4]` grant 索引键（user + client）
/// - `KEYS[5]` token 到 family 的定位键
/// - `ARGV[1]` token_hash
/// - `ARGV[2]` 索引 TTL（秒）
/// - `ARGV[3]` family_id，空表示旧格式 token
pub const REMOVE_WITHOUT_TOMBSTONE_SCRIPT: &str = r#"
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('SREM', KEYS[4], ARGV[1])
redis.call('EXPIRE', KEYS[4], ARGV[2])
redis.call('DEL', KEYS[5])
if ARGV[3] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[1])
    redis.call('EXPIRE', KEYS[3], ARGV[2])
end
return 1
"#;

/// 原子 CAS 删除 token、清理索引并写墓碑（授权码换取路径的单次消费）。
///
/// 这是唯一会写 `Consumed` 墓碑的删除脚本。先做 CAS 比较：只有当前值
/// 的 `value` + `cas_revision` 与预期一致时才消费，避免并发请求各自删掉
/// 对方刚写入的 token；未知未来字段不参与比较，以支持滚动升级。
///
/// - `KEYS[1]` token 主键
/// - `KEYS[2]` client 索引键
/// - `KEYS[3]` family 索引键（`ARGV[6]` 为空时不使用）
/// - `KEYS[4]` 墓碑键
/// - `KEYS[5]` grant 索引键（user + client）
/// - `KEYS[6]` token 到 family 的定位键
/// - `ARGV[1]` 预期 token JSON（只比较 `value` + `cas_revision`）
/// - `ARGV[2]` token_hash
/// - `ARGV[3]` 墓碑 JSON
/// - `ARGV[4]` 墓碑 TTL（秒）
/// - `ARGV[5]` 索引 TTL（秒）
/// - `ARGV[6]` family_id，空表示旧格式 token
///
/// 返回 `1` 消费成功，`0` 表示 CAS 失败。
pub const TAKE_IF_MATCHES_SCRIPT: &str = concat!(
    super::cas::cas_identity_lua!(),
    r#"
local current = redis.call('GET', KEYS[1])
if not current or not same_cas_identity(current, ARGV[1], 'value') then
    return 0
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[5])
redis.call('SREM', KEYS[5], ARGV[2])
redis.call('EXPIRE', KEYS[5], ARGV[5])
redis.call('DEL', KEYS[6])
if ARGV[6] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[2])
    redis.call('EXPIRE', KEYS[3], ARGV[5])
end
redis.call('SETEX', KEYS[4], ARGV[4], ARGV[3])
return 1
"#
);

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
/// - `KEYS[6]` grant 索引键（user + client）
/// - `ARGV[1]` token 主键前缀
/// - `ARGV[2]` 墓碑键前缀
/// - `ARGV[3]` token 到 family 的定位键前缀
/// - `ARGV[4]` 墓碑 JSON（`family_revoked` 或 `explicit_revoke`）
/// - `ARGV[5]` 墓碑 TTL（秒）
/// - `ARGV[6]` 墓志 TTL（秒），必须覆盖 family 的绝对生命周期上限
/// - `ARGV[7]` 调用方提交的 token_hash
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
    redis.call('SREM', KEYS[6], token_hash)
    redis.call('DEL', ARGV[3] .. token_hash)
    redis.call('SETEX', ARGV[2] .. token_hash, ARGV[5], ARGV[4])
end
redis.call('DEL', KEYS[1])
if redis.call('DEL', KEYS[4]) == 1 then
    removed = removed + 1
end
redis.call('DEL', ARGV[3] .. ARGV[7])
redis.call('SREM', KEYS[2], ARGV[7])
redis.call('SREM', KEYS[6], ARGV[7])
redis.call('SETEX', KEYS[5], ARGV[5], ARGV[4])
redis.call('SETEX', KEYS[3], ARGV[6], ARGV[4])
return removed
"#;

/// 撤销一个 grant（`user_id` + `client_id`）下的全部 Refresh Token。
///
/// 用户「断开应用」的撤销单元就是 grant（Issue #418）。此前撤销只写 consent
/// 行，已签发的 Refresh Token 依赖下一次兑换时的 consent 检查才失效——那是
/// check-on-use，不是撤销：一旦 consent 缓存或 DB 判定出现任何放行路径，凭据
/// 就还在。这里把凭据本身删掉。
///
/// 与 client 级撤销的关键差别是**必须写墓碑和 family 墓志**。Secret 轮换后
/// 有 `client_secret_version` 兜底，且旧凭据已在语义上失效；而 grant 撤销
/// 之后 Client 的 secret 版本不变，一次飞行中的轮换完全可以在本脚本清空索引
/// 之后把新成员写回同一个 family。墓志是那道竞态的收口点，与
/// `REVOKE_FAMILY_SCRIPT` 的理由一致。
///
/// 墓碑状态用 `explicit_revoke`：用户主动断开不是凭据泄露信号，后续提交只应
/// 得到普通 `invalid_grant`，不该被记成「检测到重放」的安全事件。
///
/// 每批最多处理 128 个成员，重复到 grant 索引清空。payload 解析失败时不确认
/// 对应成员，调用方修复后可重试。
///
/// - `KEYS[1]` grant 索引键
/// - `ARGV[1]` token 主键前缀
/// - `ARGV[2]` token 到 family 的定位键前缀
/// - `ARGV[3]` family 索引键前缀
/// - `ARGV[4]` 墓碑键前缀
/// - `ARGV[5]` 请求的批大小（脚本内硬限制为最多 128）
/// - `ARGV[6]` client 索引键
/// - `ARGV[7]` 墓碑 JSON（`explicit_revoke`）
/// - `ARGV[8]` 墓碑 TTL（秒）
/// - `ARGV[9]` family 撤销墓志键前缀
/// - `ARGV[10]` 墓志 TTL（秒）
///
/// 返回 `{被删除的 token 数量, grant 索引剩余成员数}`。
pub const REVOKE_GRANT_TOKENS_SCRIPT: &str = r#"
local batch_size = tonumber(ARGV[5])
if not batch_size or batch_size < 1 then
    return redis.error_reply('ERR invalid grant revoke batch size')
end
batch_size = math.min(batch_size, 128)
local members = redis.call('SRANDMEMBER', KEYS[1], batch_size)
local tokens = {}

local function find_family_id(token_hash)
    local mapped_family_id = redis.call('GET', ARGV[2] .. token_hash)
    if mapped_family_id then
        return mapped_family_id
    end
    -- Tokens written before the per-token mapping was introduced still need
    -- their real family index removed after the primary key expires.
    local cursor = '0'
    repeat
        local scan_result = redis.call('SCAN', cursor, 'MATCH', ARGV[3] .. '*', 'COUNT', 128)
        cursor = scan_result[1]
        for _, family_key in ipairs(scan_result[2]) do
            if redis.call('SISMEMBER', family_key, token_hash) == 1 then
                return string.sub(family_key, string.len(ARGV[3]) + 1)
            end
        end
    until cursor == '0'
    return nil
end

-- Preflight every payload before destroying anything, so a decode failure
-- leaves the whole batch retryable instead of half-revoked.
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
    if not family_id or family_id == '' then
        family_id = find_family_id(token_hash)
    end
    tokens[#tokens + 1] = {
        hash = token_hash,
        key = token_key,
        family_id = family_id
    }
end

local removed = 0
for _, token in ipairs(tokens) do
    -- 旧格式 token（空 family_id）的撤销域按 token 哈希独立，与
    -- `FamilyScope` 的 `legacy-token:{hash}` 回退保持同一键空间。
    local scope = token.family_id
    if not scope or scope == '' then
        scope = 'legacy-token:' .. token.hash
    else
        redis.call('SREM', ARGV[3] .. scope, token.hash)
    end
    -- 墓志必须比任何成员活得久，否则它过期后一次迟到的轮换又能写回该 family。
    redis.call('SETEX', ARGV[9] .. scope, ARGV[10], ARGV[7])
    if redis.call('DEL', token.key) == 1 then
        removed = removed + 1
    end
    redis.call('DEL', ARGV[2] .. token.hash)
    redis.call('SETEX', ARGV[4] .. token.hash, ARGV[8], ARGV[7])
    redis.call('SREM', ARGV[6], token.hash)
end

-- Removing the grant member is the completion acknowledgement for retries.
for _, token in ipairs(tokens) do
    redis.call('SREM', KEYS[1], token.hash)
end

return {removed, redis.call('SCARD', KEYS[1])}
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
/// - `ARGV[2]` token 到 family 的定位键前缀
/// - `ARGV[3]` family 索引键前缀
/// - `ARGV[4]` tombstone 键前缀（清理同 token 的旧 marker）
/// - `ARGV[5]` 请求的批大小（脚本内硬限制为最多 128）
/// - `ARGV[6]` grant 索引键前缀（按 payload 里的 user_id + client_id 拼装）
///
/// 返回 `{被删除的 token 数量, client 索引剩余成员数}`。
pub const REVOKE_CLIENT_TOKENS_SCRIPT: &str = r#"
local batch_size = tonumber(ARGV[5])
if not batch_size or batch_size < 1 then
    return redis.error_reply('ERR invalid client revoke batch size')
end
batch_size = math.min(batch_size, 128)
local members = redis.call('SRANDMEMBER', KEYS[1], batch_size)
local tokens = {}

local function find_family_id(token_hash)
    local mapped_family_id = redis.call('GET', ARGV[2] .. token_hash)
    if mapped_family_id then
        return mapped_family_id
    end
    -- Keep pre-upgrade tokens repairable when their primary key has expired.
    local cursor = '0'
    repeat
        local scan_result = redis.call('SCAN', cursor, 'MATCH', ARGV[3] .. '*', 'COUNT', 128)
        cursor = scan_result[1]
        for _, family_key in ipairs(scan_result[2]) do
            if redis.call('SISMEMBER', family_key, token_hash) == 1 then
                return string.sub(family_key, string.len(ARGV[3]) + 1)
            end
        end
    until cursor == '0'
    return nil
end

-- Preflight every selected payload before changing any index or token key.
for _, token_hash in ipairs(members) do
    local token_key = ARGV[1] .. token_hash
    local payload = redis.call('GET', token_key)
    local family_id = nil
    -- 必须显式 local：Redis 拒绝脚本创建全局变量。
    local grant_key = nil
    if payload then
        local decoded = cjson.decode(payload)
        if type(decoded) ~= 'table' then
            return redis.error_reply('ERR invalid refresh token payload')
        end
        family_id = decoded['family_id']
        if family_id and type(family_id) ~= 'string' then
            return redis.error_reply('ERR invalid refresh token family_id')
        end
        -- grant 索引成员也必须清掉，否则 Secret 轮换后 (user, client) 索引里
        -- 会残留已删除 token 的哈希，让后续按 grant 撤销的批次空转。
        local user_id = decoded['user_id']
        local client_id = decoded['client_id']
        if type(user_id) == 'string' and type(client_id) == 'string' then
            grant_key = ARGV[6] .. user_id .. ':' .. client_id
        end
    end
    if not family_id or family_id == '' then
        family_id = find_family_id(token_hash)
    end
    tokens[#tokens + 1] = {
        hash = token_hash,
        key = token_key,
        family_id = family_id,
        grant_key = grant_key
    }
end

-- A family index error must happen before any selected token is destroyed.
for _, token in ipairs(tokens) do
    if token.family_id and token.family_id ~= '' then
        redis.call('SREM', ARGV[3] .. token.family_id, token.hash)
    end
end

local removed = 0
for _, token in ipairs(tokens) do
    if redis.call('DEL', token.key) == 1 then
        removed = removed + 1
    end
    redis.call('DEL', ARGV[4] .. token.hash)
end

for _, token in ipairs(tokens) do
    if token.grant_key then
        redis.call('SREM', token.grant_key, token.hash)
    end
    redis.call('DEL', ARGV[2] .. token.hash)
end

-- Removing the client member is the completion acknowledgement for retries.
for _, token in ipairs(tokens) do
    redis.call('SREM', KEYS[1], token.hash)
end

return {removed, redis.call('SCARD', KEYS[1])}
"#;
