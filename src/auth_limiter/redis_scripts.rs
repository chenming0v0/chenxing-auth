// Redis Lua 脚本：AUTH 失败限流的原子操作。
pub(crate) const CHECK_LIMITS_SCRIPT: &str = r#"
for index, key in ipairs(KEYS) do
    local current = redis.call('GET', key)
    if current and tonumber(current) >= tonumber(ARGV[index]) then
        return 1
    end
end
return 0
"#;
pub(crate) const RECORD_FAILURE_SCRIPT: &str = r#"
local reached = {}
for index, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[index + 1])
    local current = tonumber(redis.call('GET', key) or '0')
    if current < limit then
        current = redis.call('INCR', key)
        if current == 1 then redis.call('EXPIRE', key, ARGV[1]) end
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
return reached
"#;
pub(crate) const RESERVE_ATTEMPT_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
for index = 1, count do
    local failures = tonumber(redis.call('GET', KEYS[index]) or '0')
    local pending = tonumber(redis.call('GET', KEYS[count + index]) or '0')
    if failures + pending >= tonumber(ARGV[index + 2]) then
        return 0
    end
end
for index = 1, count do
    local pending = redis.call('INCR', KEYS[count + index])
    if pending == 1 then redis.call('EXPIRE', KEYS[count + index], ttl) end
end
return 1
"#;
pub(crate) const RECORD_RESERVED_FAILURE_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local reached = {}
for index = 1, count do
    local pending = tonumber(redis.call('GET', KEYS[count + index]) or '0')
    if pending > 0 then
        if pending == 1 then
            redis.call('DEL', KEYS[count + index])
        else
            redis.call('DECR', KEYS[count + index])
        end
    end
    local limit = tonumber(ARGV[index + 2])
    local current = tonumber(redis.call('GET', KEYS[index]) or '0')
    if current < limit then
        current = redis.call('INCR', KEYS[index])
        if current == 1 then redis.call('EXPIRE', KEYS[index], ttl) end
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
return reached
"#;
pub(crate) const RELEASE_ATTEMPT_SCRIPT: &str = r#"
for index, key in ipairs(KEYS) do
    local pending = tonumber(redis.call('GET', key) or '0')
    if pending > 0 then
        if pending == 1 then
            redis.call('DEL', key)
        else
            redis.call('DECR', key)
        end
    end
end
return 1
"#;

