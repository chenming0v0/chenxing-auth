//! 进程内 Argon2 并发上限（Issue #658）。
//!
//! Argon2id 默认参数大约 19 MiB 内存、数十毫秒 CPU。未加界的 `spawn_blocking`
//! 会让登录洪泛把阻塞线程池和内存打满；请求超时也**不会**取消已经在跑的闭包。
//! 因此许可必须活在阻塞闭包里：丢掉 `JoinHandle` 不能在 Argon2 还在跑时腾出槽位。
//!
//! 没有空闲许可时在异步侧等待，而不是无界入队。HTTP 超时取消的是 `acquire`，
//! 不会多扔一份闭包进阻塞池。哑校验与真实校验抢同一把许可，攻击者不能靠
//! 「用户不存在」路径绕过上限。

use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

/// 即使在超大机器上，并发 Argon2 也不超过这个硬顶。
///
/// 32 × 19 MiB ≈ 608 MiB 工作内存。再往上的登录请求排队等待许可，
/// 而不是把机器换到死。
const MAX_ARGON2_CONCURRENCY: usize = 32;

fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, MAX_ARGON2_CONCURRENCY)
}

static PROCESS_GATE: OnceLock<Arc<Argon2Gate>> = OnceLock::new();

fn process_gate() -> Arc<Argon2Gate> {
    PROCESS_GATE
        .get_or_init(|| Arc::new(Argon2Gate::new(default_concurrency())))
        .clone()
}

#[cfg(test)]
tokio::task_local! {
    static TEST_GATE: Arc<Argon2Gate>;
}

pub(super) fn active_gate() -> Arc<Argon2Gate> {
    #[cfg(test)]
    if let Ok(gate) = TEST_GATE.try_with(Arc::clone) {
        return gate;
    }
    process_gate()
}

/// 只给当前 task tree 换一把闸门。生产路径从不覆盖进程级上限。
#[cfg(test)]
pub(super) async fn with_gate<F, Fut>(gate: Arc<Argon2Gate>, f: F) -> Fut::Output
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    TEST_GATE.scope(gate, f()).await
}

/// 有界 Argon2 调度的失败原因。
#[derive(Debug)]
pub(super) enum Argon2SpawnError {
    /// 信号量已关闭，没有把新工作丢进阻塞池。
    Saturated,
    /// 阻塞任务 panic，或运行时正在关闭。
    Join(tokio::task::JoinError),
}

pub(super) struct Argon2Gate {
    permits: Arc<Semaphore>,
    #[cfg(test)]
    limit: usize,
    #[cfg(test)]
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    peak: Arc<std::sync::atomic::AtomicUsize>,
}

impl Argon2Gate {
    pub(super) fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            permits: Arc::new(Semaphore::new(limit)),
            #[cfg(test)]
            limit,
            #[cfg(test)]
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            peak: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// 拿到许可后再 `spawn_blocking`。许可随闭包走，调用方超时/取消不能提前释放。
    pub(super) async fn spawn_blocking<T, F>(&self, work: F) -> Result<T, Argon2SpawnError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = match self.permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            // `AcquireError` 只在信号量关闭时出现。关闭 = 不再接受新的 Argon2。
            Err(_) => return Err(Argon2SpawnError::Saturated),
        };

        #[cfg(test)]
        let in_flight = Arc::clone(&self.in_flight);
        #[cfg(test)]
        let peak = Arc::clone(&self.peak);
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _guard = FlightGuard::enter(&in_flight, &peak);
            work()
        })
        .await
        {
            Ok(value) => Ok(value),
            Err(error) => Err(Argon2SpawnError::Join(error)),
        }
    }
}

#[cfg(test)]
struct FlightGuard {
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl FlightGuard {
    fn enter(
        in_flight: &Arc<std::sync::atomic::AtomicUsize>,
        peak: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(current, Ordering::SeqCst);
        Self {
            in_flight: Arc::clone(in_flight),
        }
    }
}

#[cfg(test)]
impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Argon2Gate {
    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn peak(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    pub(super) fn close(&self) {
        self.permits.close();
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
