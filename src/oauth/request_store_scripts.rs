pub const PENDING_CAPACITY_SCRIPT: &str = r#"
local request_prefix = 'chenxing:oauth:request:'
local client_index_prefix = 'chenxing:oauth:pending:client-requests:'
local client_count_prefix = 'chenxing:oauth:pending:client:'

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, client_count_prefix .. client_id)
    else
        redis.call('SET', client_count_prefix .. client_id, count)
        redis.call('EXPIRE', index_key, ARGV[2])
        redis.call('EXPIRE', client_count_prefix .. client_id, ARGV[2])
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[5])
    if count == 0 then
        redis.call('DEL', KEYS[5], KEYS[6], KEYS[3])
    else
        redis.call('SET', KEYS[3], count)
        redis.call('EXPIRE', KEYS[5], ARGV[2])
        redis.call('EXPIRE', KEYS[6], ARGV[2])
        redis.call('EXPIRE', KEYS[3], ARGV[2])
    end
    return count
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
    end
end
local now = tonumber(redis.call('TIME')[1])
for _, request_id in ipairs(redis.call('ZRANGEBYSCORE', KEYS[6], '-inf', now)) do
    if redis.call('EXISTS', request_prefix .. request_id) == 0 then
        release(request_id, nil)
    else
        redis.call('ZADD', KEYS[6], now + tonumber(ARGV[2]), request_id)
    end
end

local client_count = sync_client_count(ARGV[5])
local global_count = sync_global_count()
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
if client_count >= tonumber(ARGV[3]) or global_count >= tonumber(ARGV[4]) then
    return 0
end
redis.call('SETEX', KEYS[1], ARGV[2], ARGV[1])
redis.call('SADD', KEYS[4], ARGV[6])
redis.call('HSET', KEYS[5], ARGV[6], ARGV[5])
redis.call('ZADD', KEYS[6], now + tonumber(ARGV[2]), ARGV[6])
sync_client_count(ARGV[5])
sync_global_count()
return 1
"#;

pub const PENDING_TAKE_SCRIPT: &str = r#"
local client_index_prefix = 'chenxing:oauth:pending:client-requests:'
local client_count_prefix = 'chenxing:oauth:pending:client:'

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, client_count_prefix .. client_id)
    else
        redis.call('SET', client_count_prefix .. client_id, count)
        redis.call('EXPIRE', index_key, ARGV[2])
        redis.call('EXPIRE', client_count_prefix .. client_id, ARGV[2])
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        redis.call('SET', KEYS[3], count)
        redis.call('EXPIRE', KEYS[2], ARGV[2])
        redis.call('EXPIRE', KEYS[4], ARGV[2])
        redis.call('EXPIRE', KEYS[3], ARGV[2])
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
local client_id = cjson.decode(current)['client_id']
redis.call('DEL', KEYS[1])
release(ARGV[1], client_id)
return current
"#;

pub const PENDING_TAKE_IF_MATCHES_SCRIPT: &str = r#"
local client_index_prefix = 'chenxing:oauth:pending:client-requests:'
local client_count_prefix = 'chenxing:oauth:pending:client:'

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, client_count_prefix .. client_id)
    else
        redis.call('SET', client_count_prefix .. client_id, count)
        redis.call('EXPIRE', index_key, ARGV[3])
        redis.call('EXPIRE', client_count_prefix .. client_id, ARGV[3])
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        redis.call('SET', KEYS[3], count)
        redis.call('EXPIRE', KEYS[2], ARGV[3])
        redis.call('EXPIRE', KEYS[4], ARGV[3])
        redis.call('EXPIRE', KEYS[3], ARGV[3])
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
if current ~= ARGV[1] then return nil end
local client_id = cjson.decode(current)['client_id']
redis.call('DEL', KEYS[1])
release(ARGV[2], client_id)
return current
"#;

pub const PENDING_REPLACE_SCRIPT: &str = r#"
local client_index_prefix = 'chenxing:oauth:pending:client-requests:'
local client_count_prefix = 'chenxing:oauth:pending:client:'

local function sync_client_count(client_id)
    local index_key = client_index_prefix .. client_id
    local count = redis.call('SCARD', index_key)
    if count == 0 then
        redis.call('DEL', index_key, client_count_prefix .. client_id)
    else
        redis.call('SET', client_count_prefix .. client_id, count)
        redis.call('EXPIRE', index_key, ARGV[4])
        redis.call('EXPIRE', client_count_prefix .. client_id, ARGV[4])
    end
    return count
end

local function sync_global_count()
    local count = redis.call('HLEN', KEYS[2])
    if count == 0 then
        redis.call('DEL', KEYS[2], KEYS[4], KEYS[3])
    else
        redis.call('SET', KEYS[3], count)
        redis.call('EXPIRE', KEYS[2], ARGV[4])
        redis.call('EXPIRE', KEYS[4], ARGV[4])
        redis.call('EXPIRE', KEYS[3], ARGV[4])
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
if current ~= ARGV[1] then return 0 end
local current_client_id = cjson.decode(current)['client_id']
local replacement_client_id = cjson.decode(ARGV[2])['client_id']
if current_client_id ~= replacement_client_id then return 0 end
local indexed_client_id = redis.call('HGET', KEYS[2], ARGV[3])
if not indexed_client_id then
    if sync_client_count(replacement_client_id) >= tonumber(ARGV[5])
        or sync_global_count() >= tonumber(ARGV[6]) then
        return 0
    end
    redis.call('SADD', client_index_prefix .. replacement_client_id, ARGV[3])
    redis.call('HSET', KEYS[2], ARGV[3], replacement_client_id)
end
redis.call('SETEX', KEYS[1], ARGV[4], ARGV[2])
redis.call('ZADD', KEYS[4], tonumber(redis.call('TIME')[1]) + tonumber(ARGV[4]), ARGV[3])
sync_client_count(replacement_client_id)
sync_global_count()
return 1
"#;
