// Redis Lua 脚本：AUTH 失败限流的原子操作。
pub(crate) const CHECK_LIMITS_SCRIPT: &str = r#"
local window_seconds = tonumber(ARGV[1])
local time = redis.call('TIME')
local window = math.floor(tonumber(time[1]) / window_seconds)
local suffix = ':' .. window
for index, key in ipairs(KEYS) do
    local current = redis.call('GET', key .. suffix)
    if current and tonumber(current) >= tonumber(ARGV[index + 1]) then
        return {1, window}
    end
end
return {0, window}
"#;
pub(crate) const RECORD_FAILURE_SCRIPT: &str = r#"
local window_seconds = tonumber(ARGV[1])
local time = redis.call('TIME')
local seconds = tonumber(time[1])
local window = math.floor(seconds / window_seconds)
local suffix = ':' .. window
local ttl = math.ceil(((window + 1) * window_seconds) - seconds - (tonumber(time[2]) / 1000000))
if ttl < 1 then ttl = 1 end
local reached = {}
for index, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[index + 1])
    local failure_key = key .. suffix
    local current = tonumber(redis.call('GET', failure_key) or '0')
    if current < limit then
        current = redis.call('INCR', failure_key)
        if current == 1 then redis.call('EXPIRE', failure_key, ttl) end
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
reached[#KEYS + 1] = window
return reached
"#;
pub(crate) const RESERVE_ATTEMPT_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local time = redis.call('TIME')
local seconds = tonumber(time[1])
local window = math.floor(seconds / window_seconds)
local suffix = ':' .. window
local ttl = math.ceil(((window + 1) * window_seconds) - seconds - (tonumber(time[2]) / 1000000))
if ttl < 1 then ttl = 1 end
for index = 1, count do
    local failure_key = KEYS[index] .. suffix
    local pending_key = KEYS[count + index] .. suffix
    local failures = tonumber(redis.call('GET', failure_key) or '0')
    local pending = tonumber(redis.call('GET', pending_key) or '0')
    if failures + pending >= tonumber(ARGV[index + 2]) then
        return {0, window}
    end
end
for index = 1, count do
    local pending_key = KEYS[count + index] .. suffix
    local pending = redis.call('INCR', pending_key)
    if pending == 1 then redis.call('EXPIRE', pending_key, ttl) end
end
return {1, window}
"#;
pub(crate) const RECORD_RESERVED_FAILURE_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local time = redis.call('TIME')
local seconds = tonumber(time[1])
local window = math.floor(seconds / window_seconds)
local suffix = ':' .. window
local ttl = math.ceil(((window + 1) * window_seconds) - seconds - (tonumber(time[2]) / 1000000))
if ttl < 1 then ttl = 1 end
local reached = {}
for index = 1, count do
    local pending_key = KEYS[count + index] .. suffix
    local pending = tonumber(redis.call('GET', pending_key) or '0')
    if pending > 0 then
        if pending == 1 then
            redis.call('DEL', pending_key)
        else
            redis.call('DECR', pending_key)
        end
    end
    local limit = tonumber(ARGV[index + 2])
    local failure_key = KEYS[index] .. suffix
    local current = tonumber(redis.call('GET', failure_key) or '0')
    if current < limit then
        current = redis.call('INCR', failure_key)
        if current == 1 then redis.call('EXPIRE', failure_key, ttl) end
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
reached[count + 1] = window
return reached
"#;
pub(crate) const RELEASE_ATTEMPT_SCRIPT: &str = r#"
local window_seconds = tonumber(ARGV[1])
local time = redis.call('TIME')
local window = math.floor(tonumber(time[1]) / window_seconds)
local suffix = ':' .. window
for index, key in ipairs(KEYS) do
    local pending_key = key .. suffix
    local pending = tonumber(redis.call('GET', pending_key) or '0')
    if pending > 0 then
        if pending == 1 then
            redis.call('DEL', pending_key)
        else
            redis.call('DECR', pending_key)
        end
    end
end
return 1
"#;
pub(crate) const CLEAR_FAILURE_SCRIPT: &str = r#"
local window_seconds = tonumber(ARGV[1])
local time = redis.call('TIME')
local window = math.floor(tonumber(time[1]) / window_seconds)
return redis.call('DEL', KEYS[1] .. ':' .. window)
"#;
