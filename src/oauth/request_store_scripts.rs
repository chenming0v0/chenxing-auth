use super::cas::cas_identity_lua;

/// Shared-index TTL must never shrink to a sibling request's remaining life.
/// Redis `EXPIRE` overwrites; `SET` clears TTL. Restore of a near-expiry
/// request used to expire client/global indexes early and drop still-alive
/// keys from capacity accounting.
macro_rules! pending_script {
    ($body:expr) => {
        concat!(
            cas_identity_lua!(),
            r#"
local function expire_at_least(key, ttl_ms)
    ttl_ms = tonumber(ttl_ms)
    if not ttl_ms or ttl_ms <= 0 then
        return
    end
    local current = tonumber(redis.call('PTTL', key))
    if current < ttl_ms then
        redis.call('PEXPIRE', key, ttl_ms)
    end
end

local function set_count(key, count, ttl_ms)
    redis.call('SET', key, count, 'KEEPTTL')
    expire_at_least(key, ttl_ms)
end
"#,
            $body
        )
    };
}

pub const PENDING_CAPACITY_SCRIPT: &str = pending_script!(
    r#"
local request_prefix = ARGV[7]
local client_index_prefix = ARGV[8]
local client_count_prefix = ARGV[9]
local request_ttl_ms = tonumber(ARGV[10])
local ttl_seconds = tonumber(ARGV[2])
local ttl_ms = ttl_seconds * 1000
if request_ttl_ms and request_ttl_ms > 0 then
    ttl_ms = request_ttl_ms
    ttl_seconds = math.ceil(request_ttl_ms / 1000)
end

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count_key = client_count_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, count_key)
    else
        set_count(count_key, count, ttl_ms)
        expire_at_least(index_key, ttl_ms)
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[5])
    if count == 0 then
        redis.call('DEL', KEYS[5], KEYS[6], KEYS[3])
    else
        set_count(KEYS[3], count, ttl_ms)
        expire_at_least(KEYS[5], ttl_ms)
        expire_at_least(KEYS[6], ttl_ms)
    end
    return count
end

local function cover_request(request_id)
    local remaining_ms = tonumber(redis.call('PTTL', request_prefix .. request_id))
    if not remaining_ms or remaining_ms <= 0 then
        return ttl_seconds
    end
    expire_at_least(KEYS[5], remaining_ms)
    expire_at_least(KEYS[6], remaining_ms)
    expire_at_least(KEYS[3], remaining_ms)
    local owner = redis.call('HGET', KEYS[5], request_id) or ARGV[5]
    if owner then
        expire_at_least(client_index_prefix .. owner, remaining_ms)
        expire_at_least(client_count_prefix .. owner, remaining_ms)
    end
    return math.ceil(remaining_ms / 1000)
end

local function release(request_id, fallback_client_id)
    local client_id = redis.call('HGET', KEYS[5], request_id) or fallback_client_id
    if client_id then
        redis.call('SREM', client_index_prefix .. client_id, request_id)
        sync_client_count(client_id)
    end
    redis.call('HDEL', KEYS[5], request_id)
    redis.call('ZREM', KEYS[6], request_id)
    sync_global_count()
end

for _, request_id in ipairs(redis.call('SMEMBERS', KEYS[4])) do
    if redis.call('EXISTS', request_prefix .. request_id) == 0 then
        release(request_id, ARGV[5])
    else
        cover_request(request_id)
    end
end
local now = tonumber(redis.call('TIME')[1])
for _, request_id in ipairs(redis.call('ZRANGEBYSCORE', KEYS[6], '-inf', now)) do
    if redis.call('EXISTS', request_prefix .. request_id) == 0 then
        release(request_id, nil)
    else
        redis.call('ZADD', KEYS[6], now + cover_request(request_id), request_id)
    end
end

local client_count = sync_client_count(ARGV[5])
local global_count = sync_global_count()
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
if client_count >= tonumber(ARGV[3]) or global_count >= tonumber(ARGV[4]) then
    return 0
end
if request_ttl_ms and request_ttl_ms > 0 then
    redis.call('SET', KEYS[1], ARGV[1], 'PX', request_ttl_ms)
else
    redis.call('SETEX', KEYS[1], ttl_seconds, ARGV[1])
end
redis.call('SADD', KEYS[4], ARGV[6])
redis.call('HSET', KEYS[5], ARGV[6], ARGV[5])
redis.call('ZADD', KEYS[6], now + ttl_seconds, ARGV[6])
sync_client_count(ARGV[5])
sync_global_count()
return 1
"#
);

pub const PENDING_TAKE_SCRIPT: &str = pending_script!(
    r#"
local client_index_prefix = ARGV[3]
local client_count_prefix = ARGV[4]
local ttl_ms = tonumber(ARGV[2]) * 1000

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count_key = client_count_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, count_key)
    else
        set_count(count_key, count, ttl_ms)
        expire_at_least(index_key, ttl_ms)
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        set_count(KEYS[3], count, ttl_ms)
        expire_at_least(KEYS[2], ttl_ms)
        expire_at_least(KEYS[4], ttl_ms)
    end
    return count
end

local function release(request_id, fallback_client_id)
    local client_id = redis.call('HGET', KEYS[2], request_id) or fallback_client_id
    if client_id then
        redis.call('SREM', client_index_prefix .. client_id, request_id)
        sync_client_count(client_id)
    end
    redis.call('HDEL', KEYS[2], request_id)
    redis.call('ZREM', KEYS[4], request_id)
    sync_global_count()
end

local current = redis.call('GET', KEYS[1])
if not current then
    release(ARGV[1], nil)
    return nil
end
local remaining_ms = redis.call('PTTL', KEYS[1])
local client_id = cjson.decode(current)['client_id']
redis.call('DEL', KEYS[1])
release(ARGV[1], client_id)
return {current, remaining_ms}
"#
);

pub const PENDING_TAKE_IF_MATCHES_SCRIPT: &str = pending_script!(
    r#"
local client_index_prefix = ARGV[4]
local client_count_prefix = ARGV[5]
local ttl_ms = tonumber(ARGV[3]) * 1000

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count_key = client_count_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, count_key)
    else
        set_count(count_key, count, ttl_ms)
        expire_at_least(index_key, ttl_ms)
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        set_count(KEYS[3], count, ttl_ms)
        expire_at_least(KEYS[2], ttl_ms)
        expire_at_least(KEYS[4], ttl_ms)
    end
    return count
end

local function release(request_id, fallback_client_id)
    local client_id = redis.call('HGET', KEYS[2], request_id) or fallback_client_id
    if client_id then
        redis.call('SREM', client_index_prefix .. client_id, request_id)
        sync_client_count(client_id)
    end
    redis.call('HDEL', KEYS[2], request_id)
    redis.call('ZREM', KEYS[4], request_id)
    sync_global_count()
end

local current = redis.call('GET', KEYS[1])
if not current then
    release(ARGV[2], nil)
    return nil
end
if not same_cas_identity(current, ARGV[1], 'request_id') then return nil end
local remaining_ms = redis.call('PTTL', KEYS[1])
local client_id = cjson.decode(current)['client_id']
redis.call('DEL', KEYS[1])
release(ARGV[2], client_id)
return {current, remaining_ms}
"#
);

pub const PENDING_REPLACE_SCRIPT: &str = pending_script!(
    r#"
local client_index_prefix = ARGV[7]
local client_count_prefix = ARGV[8]
local ttl_ms = tonumber(ARGV[4]) * 1000

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count_key = client_count_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, count_key)
    else
        set_count(count_key, count, ttl_ms)
        expire_at_least(index_key, ttl_ms)
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        set_count(KEYS[3], count, ttl_ms)
        expire_at_least(KEYS[2], ttl_ms)
        expire_at_least(KEYS[4], ttl_ms)
    end
    return count
end

local function release(request_id, fallback_client_id)
    local client_id = redis.call('HGET', KEYS[2], request_id) or fallback_client_id
    if client_id then
        redis.call('SREM', client_index_prefix .. client_id, request_id)
        sync_client_count(client_id)
    end
    redis.call('HDEL', KEYS[2], request_id)
    redis.call('ZREM', KEYS[4], request_id)
    sync_global_count()
end

local current = redis.call('GET', KEYS[1])
if not current then
    release(ARGV[3], nil)
    return 0
end
if not same_cas_identity(current, ARGV[1], 'request_id') then return 0 end
local current_client_id = cjson.decode(current)['client_id']
local replacement_client_id = cjson.decode(ARGV[2])['client_id']
if current_client_id ~= replacement_client_id then return 0 end
local remaining_ms = tonumber(redis.call('PTTL', KEYS[1]))
if not remaining_ms or remaining_ms <= 0 then
    release(ARGV[3], current_client_id)
    return 0
end
local indexed_client_id = redis.call('HGET', KEYS[2], ARGV[3])
if not indexed_client_id then
    if sync_client_count(replacement_client_id) >= tonumber(ARGV[5])
        or sync_global_count() >= tonumber(ARGV[6]) then
        return 0
    end
    redis.call('SADD', client_index_prefix .. replacement_client_id, ARGV[3])
    redis.call('HSET', KEYS[2], ARGV[3], replacement_client_id)
end
redis.call('SET', KEYS[1], ARGV[2], 'PX', remaining_ms)
local now = redis.call('TIME')
local replacement_deadline = tonumber(now[1]) + tonumber(now[2]) / 1000000 + remaining_ms / 1000
local original_deadline = tonumber(redis.call('ZSCORE', KEYS[4], ARGV[3]))
if original_deadline and original_deadline < replacement_deadline then
    replacement_deadline = original_deadline
end
redis.call('ZADD', KEYS[4], replacement_deadline, ARGV[3])
sync_client_count(replacement_client_id)
sync_global_count()
return 1
"#
);
