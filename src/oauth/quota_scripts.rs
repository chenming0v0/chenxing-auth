pub(super) const CONSUME_SCRIPT: &str = r#"
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
local month = tonumber(redis.call('GET', KEYS[2]) or '0')
local daily_limit = tonumber(ARGV[1])
local monthly_limit = tonumber(ARGV[2])
-- 负值表示该维度不设上限（套餐里 monthly_auth_limit 为 NULL）
if daily_limit >= 0 and day >= daily_limit then
  return {0, 1, day, month}
end
if monthly_limit >= 0 and month >= monthly_limit then
  return {0, 2, day, month}
end
local new_day = redis.call('INCR', KEYS[1])
local new_month = redis.call('INCR', KEYS[2])
redis.call('HSET', KEYS[3], ARGV[5], '1')
redis.call('HSET', KEYS[4], ARGV[5], '1')
if new_day == 1 then redis.call('EXPIREAT', KEYS[1], ARGV[3]) end
if new_month == 1 then redis.call('EXPIREAT', KEYS[2], ARGV[4]) end
redis.call('EXPIREAT', KEYS[3], ARGV[3])
redis.call('EXPIREAT', KEYS[4], ARGV[4])
return {1, 0, new_day, new_month}
"#;

/// 把一次配额消耗登记为「授权码过期未兑换则退款」的待退条目（Issue #341）。
///
/// 三个命令放进同一个脚本：ZADD 与记录键写入要么同时成功要么同时失败，
/// 避免出现「有成员没记录」的半成品条目让 worker 无从退款。
///
/// KEYS[1] = 待退 ZSET；KEYS[2] = reservation 记录键
/// ARGV[1] = 授权码过期时刻的 Unix 毫秒（ZSET score，永不早于精确 expires_at）；
/// ARGV[2] = reservation id（ZSET member）
/// ARGV[3] = reservation 的 JSON（含周期键）；ARGV[4] = 记录键 EXPIREAT（月边界）
pub(super) const SCHEDULE_REFUND_SCRIPT: &str = r#"
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
redis.call('EXPIREAT', KEYS[2], ARGV[4])
return 1
"#;

pub(super) const REFUND_SCRIPT: &str = r#"
local refunded = 0
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
if day > 0 and redis.call('HDEL', KEYS[3], ARGV[1]) == 1 then
  redis.call('DECR', KEYS[1])
  refunded = 1
elseif day <= 0 then
  redis.call('HDEL', KEYS[3], ARGV[1])
end
local month = tonumber(redis.call('GET', KEYS[2]) or '0')
if month > 0 and redis.call('HDEL', KEYS[4], ARGV[1]) == 1 then
  redis.call('DECR', KEYS[2])
  refunded = 1
elseif month <= 0 then
  redis.call('HDEL', KEYS[4], ARGV[1])
end
return refunded
"#;
