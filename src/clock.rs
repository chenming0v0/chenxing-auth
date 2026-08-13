//! 进程内的时间来源边界。
//!
//! 认证平台的安全判定几乎都是时间判定：授权码是否过期、Refresh Token 是否
//! 超出绝对生命周期、Session 是否 idle、MFA ticket 是否还在 5 分钟窗口内。
//! 这些判定必须能在测试里被精确驱动到边界的两侧，而不是靠真实等待。
//!
//! 因此生命周期相关的时间一律经过 [`SharedClock`]：它在 `AppState` 里构造一次，
//! 克隆给需要判定时间的 store 与 service，生产使用 [`SystemClock`]，测试注入
//! [`FixedClock`]。
//!
//! # 保留墙钟的例外
//!
//! 不是所有时间读取都应该走注入的时钟。以下入口刻意保留外部权威时钟，并在
//! 各自的调用点标注原因：
//!
//! - Redis Lua 脚本里的 `redis.call('TIME')`：限流窗口、State 存储和授权请求
//!   存储需要**所有实例看到同一个时钟**。用调用方进程的时间会让时钟漂移变成
//!   可利用的限流绕过。
//! - PostgreSQL 语句里的 `NOW()`：会话表、outbox 和套餐到期的权威判定在数据库
//!   事务内完成，必须与行锁看到同一个事务时间。
//! - `key_lock` 的文件 mtime 与 `SystemTime`：判定的是文件系统事实，不是业务
//!   生命周期。
//! - `tokio::time::Instant`：只用于任务调度间隔，不参与任何凭据有效性判定。

use std::{fmt, sync::Arc};

use time::OffsetDateTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// 可克隆的共享时钟句柄。
///
/// `Arc<dyn Clock>` 而不是泛型参数：时钟要穿过 `AppState` 传给十来个 store 和
/// service，泛型化会让每个持有者都带上一个类型参数，进而污染 Axum handler 的
/// 签名。时钟读取不在热路径的瓶颈上，一次虚调用换来的是零类型参数扩散。
#[derive(Clone)]
pub struct SharedClock(Arc<dyn Clock>);

impl SharedClock {
    pub fn new(clock: impl Clock + 'static) -> Self {
        Self(Arc::new(clock))
    }

    /// 生产时钟。
    pub fn system() -> Self {
        Self::new(SystemClock)
    }

    /// 停在某一时刻的测试时钟。
    ///
    /// 边界测试用两个固定时钟表达「到期前」与「到期后」，不需要真实等待，
    /// 也不需要让被测对象持有可变状态。
    pub fn fixed(now: OffsetDateTime) -> Self {
        Self::new(FixedClock(now))
    }

    pub fn now(&self) -> OffsetDateTime {
        self.0.now()
    }
}

impl Default for SharedClock {
    fn default() -> Self {
        Self::system()
    }
}

impl Clock for SharedClock {
    fn now(&self) -> OffsetDateTime {
        self.0.now()
    }
}

impl fmt::Debug for SharedClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedClock").field(&self.now()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, FixedClock, SharedClock, SystemClock};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn fixed_clock_returns_the_configured_time() {
        let fixed = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(FixedClock(fixed).now(), fixed);
    }

    #[test]
    fn system_clock_reads_current_utc_time() {
        let before = OffsetDateTime::now_utc();
        let now = SystemClock.now();
        let after = OffsetDateTime::now_utc();

        assert!(before <= now && now <= after);
    }

    /// 克隆后的句柄必须指向同一个时钟实现，否则把它传给多个 store 之后
    /// 各处看到的"现在"会不一致，边界测试也就失去意义。
    #[test]
    fn shared_clock_clones_keep_reading_the_same_source() {
        let fixed = OffsetDateTime::UNIX_EPOCH + Duration::days(7);
        let clock = SharedClock::fixed(fixed);
        let cloned = clock.clone();

        assert_eq!(clock.now(), fixed);
        assert_eq!(cloned.now(), fixed);
    }

    /// 默认句柄是生产时钟：忘记显式注入时不会静默停在某个固定时刻。
    #[test]
    fn default_shared_clock_reads_the_system_clock() {
        let before = OffsetDateTime::now_utc();
        let now = SharedClock::default().now();
        let after = OffsetDateTime::now_utc();

        assert!(before <= now && now <= after);
    }

    /// `SharedClock` 自身实现 `Clock`，因此可以被再次包装或按 trait 传递。
    #[test]
    fn shared_clock_satisfies_the_clock_trait() {
        fn read(clock: &dyn Clock) -> OffsetDateTime {
            clock.now()
        }

        let fixed = OffsetDateTime::UNIX_EPOCH + Duration::hours(3);
        assert_eq!(read(&SharedClock::fixed(fixed)), fixed);
    }
}
