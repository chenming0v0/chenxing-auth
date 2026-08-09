#![allow(dead_code)]

//! 测试专用的 QPS 滑动窗口注入。
//!
//! `POST /oauth/token` 在 `enforce_qps` 之前必须先跑一次 19 MiB 的 Argon2 校验
//! （`src/clients/credentials/constant_time.rs`，反计时预言机设计，不能绕过也不能
//! 重排）。两发请求本地就要烧掉约 400ms，2 核 CI 上叠加覆盖率插桩和并发测试后会
//! 超过生产的 1000ms 窗口：第一发的 ZSET 条目被逐出，「第二发必被限流」的断言
//! 就随机变成 400 而不是 429。
//!
//! 解法是把窗口注入成一个远大于任何测试耗时的值，让「两发落在同一个窗口内」从
//! 「大概率」变成确定事实。生产窗口不变，仍然由 `QpsRateLimiter::new` 提供。

use chenxing_auth::{oauth::rate_limit::QpsRateLimiter, state::AppState};

/// 测试窗口：60 秒。
///
/// 取值只需要「远大于单个测试的挂钟耗时」。60s 相对最慢的 CI 上两发 token 请求
/// （约 2~3s）仍有一个数量级的余量，同时短到不会让 Redis key 长期堆积。
///
/// 注意：任何依赖「窗口过期后重新放行」的测试都不能用这个窗口，必须自己用
/// `QpsRateLimiter::with_window_ms` 构造一个小窗口的 limiter。
pub const TEST_QPS_WINDOW_MS: i64 = 60_000;

/// 把 `state.qps` 换成大窗口版本，消除测试对墙上时钟的依赖。
///
/// 复用 `state.redis`，因此 Redis key 空间与生产路径完全一致，只有窗口长度不同。
pub fn override_qps_window(state: &mut AppState) {
    state.qps = QpsRateLimiter::with_window_ms(state.redis.clone(), TEST_QPS_WINDOW_MS);
}
