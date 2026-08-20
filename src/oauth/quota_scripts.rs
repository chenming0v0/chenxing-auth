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

/// 把 reservation hash 重新标成可退。兑换 CAS 会 HDEL 这些 hash 而不 DECR；
/// 补偿恢复授权码时必须把 claim token 还回去，否则过期 worker 无法退款。
macro_rules! restore_reservation_hashes_lua {
    () => {
        r#"
local function restore_reservation_hashes(record_json, reservation_id)
  if not record_json then
    return
  end
  local reservation = cjson.decode(record_json)
  if type(reservation) ~= 'table' then
    return
  end
  if reservation['day_reservations_key'] then
    redis.call('HSET', reservation['day_reservations_key'], reservation_id, '1')
    if reservation['month_expires_at'] then
      redis.call('EXPIREAT', reservation['day_reservations_key'], reservation['month_expires_at'])
    end
  end
  if reservation['month_reservations_key'] then
    redis.call('HSET', reservation['month_reservations_key'], reservation_id, '1')
    if reservation['month_expires_at'] then
      redis.call('EXPIREAT', reservation['month_reservations_key'], reservation['month_expires_at'])
    end
  end
end
"#
    };
}

/// 补偿路径重新入队待退成员，并把兑换 CAS 拿走的 hash claim 还回去。
///
/// KEYS[1] = 待退 ZSET；KEYS[2] = reservation 记录键
/// ARGV[1] = score；ARGV[2] = reservation id
pub(super) const RESCHEDULE_REFUND_SCRIPT: &str = concat!(
    restore_reservation_hashes_lua!(),
    r#"
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
restore_reservation_hashes(redis.call('GET', KEYS[2]), ARGV[2])
return 1
"#
);

/// 周期计数器上的 reservation hash 是「这次 INCR 仍可退款」的一次性 claim。
/// HDEL 成功才能 DECR：兑换 CAS 先 HDEL 且不 DECR，之后这里只能空操作。
///
/// KEYS[1]=day KEYS[2]=month KEYS[3]=day hash KEYS[4]=month hash
/// 可选 KEYS[5]=待退 ZSET：worker 传入时先 ZREM，成员已被兑换拿走则直接返回 0。
/// ARGV[1]=reservation id
pub(super) const REFUND_SCRIPT: &str = r#"
if #KEYS >= 5 then
  if redis.call('ZREM', KEYS[5], ARGV[1]) == 0 then
    return 0
  end
end
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

/// 与授权码 CAS 拼在同一个脚本里：先声明 hash 已被兑换占用（HDEL 不 DECR），
/// 再删除授权码并 ZREM 待退成员。hash 已被退款脚本拿走则 fail-closed，授权码留下。
///
/// KEYS[1]=授权码 KEYS[2]=待退 ZSET KEYS[3]=reservation 记录键
/// ARGV[1]=期望 JSON ARGV[2]=reservation id（空串 = 无配额，纯 CAS）
///
/// 必须是 macro：调用方用 `concat!` 接到 CAS identity Lua 后面。
macro_rules! take_code_and_claim_quota_lua {
    () => {
        r#"
local current_json = redis.call('GET', KEYS[1])
if not current_json then
    return 0
end
if not same_cas_identity(current_json, ARGV[1], 'value') then
    return 0
end
if ARGV[2] ~= '' then
    local record = redis.call('GET', KEYS[3])
    if not record then
        return 0
    end
    local reservation = cjson.decode(record)
    local claimed = 0
    if type(reservation) == 'table' then
        if reservation['day_reservations_key'] then
            claimed = claimed + redis.call('HDEL', reservation['day_reservations_key'], ARGV[2])
        end
        if reservation['month_reservations_key'] then
            claimed = claimed + redis.call('HDEL', reservation['month_reservations_key'], ARGV[2])
        end
    end
    if claimed == 0 then
        return 0
    end
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[2])
    return 1
end
redis.call('DEL', KEYS[1])
return 1
"#
    };
}
pub(super) use take_code_and_claim_quota_lua;

/// 恢复已消费的授权码，并把待退成员和 hash claim 一并放回。
///
/// KEYS[1]=授权码 KEYS[2]=待退 ZSET KEYS[3]=reservation 记录键
/// ARGV[1]=payload ARGV[2]=TTL 毫秒 ARGV[3]=reservation id ARGV[4]=ZSET score
pub(super) const RESTORE_CODE_AND_QUOTA_SCRIPT: &str = concat!(
    restore_reservation_hashes_lua!(),
    r#"
local ttl_ms = tonumber(ARGV[2])
if ttl_ms and ttl_ms > 0 then
    redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl_ms, 'NX')
end
if ARGV[3] ~= '' then
    redis.call('ZADD', KEYS[2], tonumber(ARGV[4]), ARGV[3])
    restore_reservation_hashes(redis.call('GET', KEYS[3]), ARGV[3])
end
return 1
"#
);
