// Redis Lua 脚本：AUTH 失败限流的原子操作。
//
// 失败计数是 ZSET 滑动窗口：member 唯一、score 为 Redis 服务端毫秒时间。
// 之前的实现把 `:floor(time / window)` 追加到 key 上做 epoch 对齐固定窗口，
// 那样窗口边界是公开可预测的墙钟整点，攻击者在边界前后各打满一次配额就能在
// 两秒内获得 2× 尝试次数；同一份计数还会因为跨过整点而凭空归零。
// 滑动窗口把语义变成「任意连续 window 秒内最多 limit 次」，边界从结构上消失。
// 形状与 `src/oauth/rate_limit.rs` 的 QPS 限流一致：服务端时间 + ZSET 原子判定。
//
// pending 预留仍是普通计数器：它衡量「此刻在途的尝试数」，不是窗口内的历史事件，
// 没有需要老化的时间维度。TTL 只作为泄漏兜底，且仅在 0→1 时设置、之后不刷新——
// 若每次 INCR 都刷新，一个没能归还的预留会被后续流量永久续命，长期占用配额。
//
// 时间戳一律取自 Redis 的 `TIME`，不使用调用方时钟：多实例部署下各进程时钟不一致，
// 而限流判定必须建立在单一权威时间源上。
//
// 升级注意：新 key 不带窗口后缀，与旧版本的 `...:<hash>:<bucket>` 是不同的 key，
// 因此没有 WRONGTYPE 冲突，旧 key 也会自行到期回收。但新旧实例互相看不到对方的计数，
// 并存期间同一账户可能各拿一份配额。这一版应协调切换而不是普通滚动部署；
// 若必须滚动，需要在兼容期内双读旧 bucket，不能假装状态是连续的。

/// 各脚本内联的毫秒时间推导方式。仅用于测试断言四个脚本没有各自漂移，
/// 生产路径直接内联同一段 Lua（Redis 不支持在脚本间共享代码片段）。
#[cfg(test)]
const MILLIS_NOW: &str = r#"
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
"#;

/// 只读检查：ZCOUNT 统计窗口内的失败数，不做清理也不写入。
///
/// 返回第一个触发上限的维度下标（1-based），0 表示没有维度触发。
/// 与 `RESERVE_ATTEMPT_SCRIPT` 共用这个约定，调用方据此只给真正触发的维度打日志。
///
/// 下界用排他区间 `(cutoff`：恰好落在 `now - window` 的条目已满一个窗口，属于窗口外。
/// 与写路径 `ZREMRANGEBYSCORE ... cutoff`（含 cutoff）的边界判断一致。
/// 保持只读是有意的——`is_limited` 不应产生写命令。
///
/// 下界必须拼接 `(` 前缀，所以这里无论如何都要构造字符串；顺手用 `%d` 显式格式化。
/// Lua 5.1 把数字转成 Redis 参数时走 `%.14g`，有效位到 15 位以上会退化成科学计数法
/// 而被 Redis 当作非法 range 参数——写路径交给 `redis.call` 的裸数字同样经过这层
/// 转换，并不豁免。当前毫秒时间戳 13 位，两条路径都没有实际风险，真要触发得等到
/// 时间戳涨到 15 位（数千年尺度）。显式格式化只是让这条约束在代码里看得见。
pub(crate) const CHECK_LIMITS_SCRIPT: &str = r#"
local window = tonumber(ARGV[1]) * 1000
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
local cutoff = string.format('(%d', now - window)
for index, key in ipairs(KEYS) do
    if redis.call('ZCOUNT', key, cutoff, '+inf') >= tonumber(ARGV[index + 1]) then
        return index
    end
end
return 0
"#;

/// 记录一次失败。返回每个维度是否达到阈值。
///
/// `current < limit` 才写入：计数在阈值处饱和，不随攻击持续无界增长。
/// 达到阈值时不再 ZADD，因此也不刷新 TTL——被锁定的账户不会被攻击者的持续流量
/// 无限续期，窗口内最后一条失败老化后 key 自然消失。
pub(crate) const RECORD_FAILURE_SCRIPT: &str = r#"
local window_seconds = tonumber(ARGV[1])
local window = window_seconds * 1000
local member = ARGV[2]
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
local cutoff = now - window
local ttl = window_seconds + 1
local reached = {}
for index, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[index + 2])
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local current = redis.call('ZCARD', key)
    if current < limit then
        current = current + redis.call('ZADD', key, now, member .. ':' .. index)
        redis.call('EXPIRE', key, ttl)
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
return reached
"#;

/// 预留一次尝试：先判定全部维度，再统一 INCR pending。
///
/// 两段式是必须的——边判边写会在中途拒绝时留下已写入的 pending，
/// 让一次被拒的请求永久吃掉其他维度的配额。
/// 判定口径是 `失败数 + 在途数 >= limit`：昂贵的密码校验（Argon2）在预留通过之后
/// 才执行，若只看已记录的失败，并发请求会在第一次失败落库前全部挤进来。
///
/// 返回第一个触发上限的维度下标（1-based），0 表示预留成功。与
/// `CHECK_LIMITS_SCRIPT` 共用同一约定。
pub(crate) const RESERVE_ATTEMPT_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local window = window_seconds * 1000
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
local cutoff = now - window
local ttl = window_seconds + 1
for index = 1, count do
    local failure_key = KEYS[index]
    redis.call('ZREMRANGEBYSCORE', failure_key, '-inf', cutoff)
    local failures = redis.call('ZCARD', failure_key)
    local pending = tonumber(redis.call('GET', KEYS[count + index]) or '0')
    if failures + pending >= tonumber(ARGV[index + 2]) then
        return index
    end
end
for index = 1, count do
    local pending_key = KEYS[count + index]
    if redis.call('INCR', pending_key) == 1 then
        redis.call('EXPIRE', pending_key, ttl)
    end
end
return 0
"#;

/// 把预留提交为一次真实失败：归还 pending 并写入失败记录，一次原子完成。
/// 拆成两次往返会让崩溃窗口里的预留悬挂，或让失败计数丢失。
pub(crate) const RECORD_RESERVED_FAILURE_SCRIPT: &str = r#"
local count = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local window = window_seconds * 1000
local member = ARGV[3]
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
local cutoff = now - window
local ttl = window_seconds + 1
local reached = {}
for index = 1, count do
    local pending_key = KEYS[count + index]
    local pending = tonumber(redis.call('GET', pending_key) or '0')
    if pending > 0 then
        if pending == 1 then
            redis.call('DEL', pending_key)
        else
            redis.call('DECR', pending_key)
        end
    end
    local limit = tonumber(ARGV[index + 3])
    local failure_key = KEYS[index]
    redis.call('ZREMRANGEBYSCORE', failure_key, '-inf', cutoff)
    local current = redis.call('ZCARD', failure_key)
    if current < limit then
        current = current + redis.call('ZADD', failure_key, now, member .. ':' .. index)
        redis.call('EXPIRE', failure_key, ttl)
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
return reached
"#;

/// 认证成功后归还预留。只动 pending，不触碰失败历史：
/// 密码正确本身不构成「清空失败计数」的理由，那一步由会话签发后的 clear 负责。
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

/// 清空某个维度的失败历史。滑动窗口下 key 不再带窗口后缀，一次 DEL 即可，
/// 不会像固定窗口那样漏掉「上一个窗口的残余计数」。
pub(crate) const CLEAR_FAILURE_SCRIPT: &str = r#"
return redis.call('DEL', KEYS[1])
"#;

#[cfg(test)]
mod tests {
    /// 所有脚本都必须用 Redis 服务端时间。调用方时钟在多实例部署下不一致，
    /// 而限流判定必须建立在单一权威时间源上。这条约束容易在后续改动中被无声破坏。
    #[test]
    fn every_script_reads_time_from_redis() {
        for (name, script) in [
            ("check", super::CHECK_LIMITS_SCRIPT),
            ("record", super::RECORD_FAILURE_SCRIPT),
            ("reserve", super::RESERVE_ATTEMPT_SCRIPT),
            ("record_reserved", super::RECORD_RESERVED_FAILURE_SCRIPT),
        ] {
            assert!(
                script.contains("redis.call('TIME')"),
                "{name} script must derive time from Redis, not the caller"
            );
        }
    }

    /// 廉价烟雾检查，不是结构性防线：它只匹配一个精确字符串，改个变量名或换种写法
    /// 就能绕过。真正的回归防线是 `redis_tests` 里的跨边界行为测试
    /// `failures_survive_a_fixed_window_boundary_crossing`。这条留着是因为它零成本，
    /// 且能在有人照抄旧写法时立刻响。
    #[test]
    fn no_script_buckets_keys_by_epoch_window() {
        for (name, script) in [
            ("check", super::CHECK_LIMITS_SCRIPT),
            ("record", super::RECORD_FAILURE_SCRIPT),
            ("reserve", super::RESERVE_ATTEMPT_SCRIPT),
            ("record_reserved", super::RECORD_RESERVED_FAILURE_SCRIPT),
            ("release", super::RELEASE_ATTEMPT_SCRIPT),
            ("clear", super::CLEAR_FAILURE_SCRIPT),
        ] {
            assert!(
                !script.contains("math.floor(seconds / window_seconds)"),
                "{name} script must not bucket keys by an epoch-aligned window"
            );
        }
    }

    /// 只读路径不得产生写命令。
    #[test]
    fn the_check_script_stays_read_only() {
        for command in ["ZADD", "ZREMRANGEBYSCORE", "INCR", "EXPIRE", "DEL"] {
            assert!(
                !super::CHECK_LIMITS_SCRIPT.contains(command),
                "check script must stay read-only, found {command}"
            );
        }
    }

    /// `MILLIS_NOW` 记录的是各脚本内联的毫秒时间推导方式；
    /// 若它与脚本实际写法脱节，注释就会误导后续改动。
    #[test]
    fn the_millisecond_clock_snippet_matches_the_scripts() {
        let snippet = super::MILLIS_NOW.trim();
        for (name, script) in [
            ("check", super::CHECK_LIMITS_SCRIPT),
            ("record", super::RECORD_FAILURE_SCRIPT),
            ("reserve", super::RESERVE_ATTEMPT_SCRIPT),
            ("record_reserved", super::RECORD_RESERVED_FAILURE_SCRIPT),
        ] {
            assert!(
                script.contains(snippet),
                "{name} script must derive milliseconds exactly as MILLIS_NOW documents"
            );
        }
    }
}
