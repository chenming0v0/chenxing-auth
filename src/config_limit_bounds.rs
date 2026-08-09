//! 安全限流阈值的取值上界（#260）。
//!
//! `SecurityLimits`（环境变量）与 `SecurityLimitsSetting`（管理 API / 已持久化值）
//! 是同一组阈值的不同入口。这里同时集中两件事：
//!
//! 1. 每一项的上界常量，附带「为什么是这个数量级」的理由；
//! 2. 字段清单本身（`for_each_security_limit!`）。
//!
//! 集中清单不是为了少写代码，而是因为各入口自己枚举字段时漏一项就等于漏一道防线——
//! #260 正是这么来的：只有 `unauthenticated_source_qps` 有上界，其余 12 项可以填到
//! `i64::MAX`，管理员因此能在不触发任何拒绝的情况下关掉暴力破解防护。
//!
//! 下界统一是 1，不单独建表：QPS/TTL 为 0 表示「拒绝一切」或「凭据签发即过期」，
//! i64 阈值 `<= 0` 在 Redis Lua 比较里等价于「立即触发限流」，两者都只可能是配置错误。
//!
//! 上界的取值原则是「远高于任何真实部署需要，但仍能让防护生效」。阈值本身就是安全
//! 控制，允许写入极值等于允许静默关掉这项控制，而且从 UI 上完全看不出异常。

/// 未认证来源 QPS 上限（次/秒）。滑动窗口用 Redis ZSET 逐请求记录 member，
/// 过大的阈值会让单个源 IP 的窗口无限增长，把限流器本身变成内存放大器。
pub const MAX_UNAUTHENTICATED_SOURCE_QPS: u32 = 1_000;

/// 授权码 TTL 上限（秒）。RFC 6749 §4.1.2 要求授权码短时有效，并明确建议不超过
/// 10 分钟。授权码是一次性凭据，兑换由客户端后端立即发起，不存在需要更长窗口的
/// 合法场景；拉长的只有「已泄露但尚未兑换」的攻击窗口。
pub const MAX_AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;

/// 待决授权请求 TTL 上限（秒）。这是用户停留在授权确认页的最长时间，1 小时已经
/// 覆盖「打开页面去开会再回来」；更长只是让未完成的请求在 Redis 里堆积更久。
pub const MAX_PENDING_REQUEST_TTL_SECONDS: u64 = 3_600;

/// 单 Client 待决授权请求容量上限（个）。默认 20，此处是默认值的 500 倍；再高就
/// 等于取消单 Client 容量控制，一个 Client 即可独占全局配额。
pub const MAX_PENDING_REQUESTS_PER_CLIENT: u64 = 10_000;

/// 全局待决授权请求容量上限（个）。上界由 Redis 内存而非业务需要决定：每个待决
/// 请求都是一条带 TTL 的记录，百万级已经属于洪泛而不是正常流量。
pub const MAX_PENDING_REQUESTS_GLOBAL: u64 = 1_000_000;

/// 认证失败计数窗口上限（秒）。固定窗口 24 小时意味着失败计数一天才清零，已经是
/// 实际可用的最严策略；更长只会长期锁死正常用户，并让计数键长期驻留 Redis。
pub const MAX_AUTH_FAILURE_WINDOW_SECONDS: i64 = 86_400;

/// 单账户失败次数上限（次/窗口）。默认 10，上界取 1000：常见弱口令字典在 1000 次
/// 尝试内就足以命中，超过这个量级的「限额」等于没有账户锁定。
pub const MAX_ACCOUNT_FAILURE_LIMIT: i64 = 1_000;

/// 单源 IP 失败次数上限（次/窗口）。比账户维度宽一个数量级，因为 NAT 和企业出口
/// 后面可能有成千上万个合法用户共享一个 IP；但仍必须有界，否则 IP 维度形同关闭。
pub const MAX_IP_FAILURE_LIMIT: i64 = 10_000;

/// 单个 TOTP 登录 ticket 允许的累计失败次数。6 位动态口令只有 10^6 种取值，单
/// ticket 100 次尝试已经把猜中概率放大到万分之一；再放宽等于把 TOTP 降级成可在线
/// 爆破的口令。
pub const MAX_TOTP_TICKET_FAILURE_LIMIT: i64 = 100;

/// 外部登录 state TTL 上限（秒）。state 只需覆盖「跳到外部 IdP 完成登录再回跳」，
/// 1 小时足够；更长会让一个可重放的回跳凭据长期有效。
pub const MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS: u64 = 3_600;

/// 外部登录 state 限流窗口上限（秒）。与 state TTL 同量级即可，窗口比凭据生命周期
/// 长得多没有意义。
pub const MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS: u64 = 3_600;

/// 单窗口内单源 IP 可创建的外部登录 state 上限（个）。与 IP 失败维度同量级，兼容
/// 共享出口，同时保留对「刷 state」洪泛的约束。
pub const MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT: i64 = 10_000;

/// 外部登录 state 全局待决容量上限（个）。同样由 Redis 内存决定。
pub const MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING: i64 = 1_000_000;

/// 把 13 个安全阈值的「字段名 / 上界 / 环境变量名」清单集中到一处，交给调用方提供的
/// `$check` 宏逐字段展开。
///
/// 只有清单是共享的，动作不共享：启动期与回读期越界回退默认值并告警，管理 API 越界
/// 直接拒绝并回报字段名。因此 `$check` 自己写 `< 1 || > $max` 的判断和后续动作，
/// 这里只保证「没有任何入口能漏掉字段」。
macro_rules! for_each_security_limit {
    ($check:ident) => {
        $check!(
            unauthenticated_source_qps,
            $crate::config::MAX_UNAUTHENTICATED_SOURCE_QPS,
            "UNAUTHENTICATED_SOURCE_QPS"
        );
        $check!(
            authorization_code_ttl_seconds,
            $crate::config::MAX_AUTHORIZATION_CODE_TTL_SECONDS,
            "AUTHORIZATION_CODE_TTL_SECONDS"
        );
        $check!(
            pending_request_ttl_seconds,
            $crate::config::MAX_PENDING_REQUEST_TTL_SECONDS,
            "PENDING_REQUEST_TTL_SECONDS"
        );
        $check!(
            max_pending_requests_per_client,
            $crate::config::MAX_PENDING_REQUESTS_PER_CLIENT,
            "MAX_PENDING_REQUESTS_PER_CLIENT"
        );
        $check!(
            max_pending_requests_global,
            $crate::config::MAX_PENDING_REQUESTS_GLOBAL,
            "MAX_PENDING_REQUESTS_GLOBAL"
        );
        $check!(
            auth_failure_window_seconds,
            $crate::config::MAX_AUTH_FAILURE_WINDOW_SECONDS,
            "AUTH_FAILURE_WINDOW_SECONDS"
        );
        $check!(
            account_failure_limit,
            $crate::config::MAX_ACCOUNT_FAILURE_LIMIT,
            "ACCOUNT_FAILURE_LIMIT"
        );
        $check!(
            ip_failure_limit,
            $crate::config::MAX_IP_FAILURE_LIMIT,
            "IP_FAILURE_LIMIT"
        );
        $check!(
            totp_ticket_failure_limit,
            $crate::config::MAX_TOTP_TICKET_FAILURE_LIMIT,
            "TOTP_TICKET_FAILURE_LIMIT"
        );
        $check!(
            external_login_state_ttl_seconds,
            $crate::config::MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS,
            "EXTERNAL_LOGIN_STATE_TTL_SECONDS"
        );
        $check!(
            external_login_state_rate_window_seconds,
            $crate::config::MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
            "EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS"
        );
        $check!(
            external_login_state_rate_limit,
            $crate::config::MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT,
            "EXTERNAL_LOGIN_STATE_RATE_LIMIT"
        );
        $check!(
            external_login_state_max_pending,
            $crate::config::MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING,
            "EXTERNAL_LOGIN_STATE_MAX_PENDING"
        );
    };
}

pub(crate) use for_each_security_limit;
