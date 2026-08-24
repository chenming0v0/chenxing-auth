//! Critical background worker lifecycle, progress, and bounded shutdown supervision.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

mod supervisor;

pub use supervisor::{
    WORKER_DRAIN_TIMEOUT, WorkerContext, WorkerDrainError, WorkerFailure, WorkerSupervisor,
};

pub const WORKER_COUNT: usize = 5;
const NEVER_RECORDED: u64 = 0;
const TEST_ALWAYS_FRESH: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerName {
    IssuerSync,
    SessionOutbox,
    EmailOutbox,
    KeySync,
    QuotaRefund,
}

impl WorkerName {
    pub const ALL: [Self; WORKER_COUNT] = [
        Self::IssuerSync,
        Self::SessionOutbox,
        Self::EmailOutbox,
        Self::KeySync,
        Self::QuotaRefund,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssuerSync => "issuer_sync",
            Self::SessionOutbox => "session_outbox",
            Self::EmailOutbox => "email_outbox",
            Self::KeySync => "key_sync",
            Self::QuotaRefund => "quota_refund",
        }
    }

    pub const fn policy(self) -> WorkerPolicy {
        match self {
            Self::IssuerSync => WorkerPolicy::new(Duration::from_secs(10), Duration::from_secs(10)),
            Self::SessionOutbox => {
                WorkerPolicy::new(Duration::from_secs(10), Duration::from_secs(10))
            }
            Self::EmailOutbox => {
                WorkerPolicy::new(Duration::from_secs(10), Duration::from_secs(10))
            }
            Self::KeySync => WorkerPolicy::new(Duration::from_secs(20), Duration::from_secs(30)),
            Self::QuotaRefund => {
                WorkerPolicy::new(Duration::from_secs(150), Duration::from_secs(180))
            }
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::IssuerSync => 0,
            Self::SessionOutbox => 1,
            Self::EmailOutbox => 2,
            Self::KeySync => 3,
            Self::QuotaRefund => 4,
        }
    }
}

impl fmt::Display for WorkerName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WorkerPolicy {
    pub heartbeat_timeout: Duration,
    pub success_timeout: Duration,
    pub max_consecutive_failures: u32,
}

impl WorkerPolicy {
    const fn new(heartbeat_timeout: Duration, success_timeout: Duration) -> Self {
        Self {
            heartbeat_timeout,
            success_timeout,
            max_consecutive_failures: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkerPhase {
    Starting = 0,
    Running = 1,
    Draining = 2,
    Stopped = 3,
    Failed = 4,
}

impl WorkerPhase {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Draining,
            3 => Self::Stopped,
            4 => Self::Failed,
            _ => Self::Starting,
        }
    }
}

struct WorkerSlot {
    phase: AtomicU8,
    last_heartbeat_millis: AtomicU64,
    last_success_millis: AtomicU64,
    consecutive_failures: AtomicU32,
    reported_unready: AtomicBool,
}

impl WorkerSlot {
    fn new() -> Self {
        Self {
            phase: AtomicU8::new(WorkerPhase::Starting as u8),
            last_heartbeat_millis: AtomicU64::new(NEVER_RECORDED),
            last_success_millis: AtomicU64::new(NEVER_RECORDED),
            consecutive_failures: AtomicU32::new(0),
            reported_unready: AtomicBool::new(false),
        }
    }
}

struct WorkerHealthInner {
    epoch: Instant,
    shutting_down: AtomicBool,
    supervisor_failed: AtomicBool,
    slots: [WorkerSlot; WORKER_COUNT],
}

#[derive(Clone)]
pub struct WorkerHealth {
    inner: Arc<WorkerHealthInner>,
}

impl WorkerHealth {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WorkerHealthInner {
                epoch: Instant::now(),
                shutting_down: AtomicBool::new(false),
                supervisor_failed: AtomicBool::new(false),
                slots: [
                    WorkerSlot::new(),
                    WorkerSlot::new(),
                    WorkerSlot::new(),
                    WorkerSlot::new(),
                    WorkerSlot::new(),
                ],
            }),
        }
    }

    pub fn reporter(&self, worker: WorkerName) -> WorkerReporter {
        WorkerReporter {
            health: self.clone(),
            worker,
        }
    }

    pub fn status(&self, worker: WorkerName) -> WorkerStatus {
        self.status_at(worker, Instant::now())
    }

    pub fn readiness(&self) -> WorkerReadiness {
        let now = Instant::now();
        let workers = WorkerName::ALL.map(|worker| self.status_at(worker, now));
        WorkerReadiness {
            ready: !self.inner.supervisor_failed.load(Ordering::Acquire)
                && workers.iter().all(|worker| worker.ready),
            workers,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.readiness().ready
    }

    /// Primes direct-router integration fixtures that intentionally bypass `main` and its
    /// supervisor. Production startup must never call this; real workers earn readiness by
    /// reporting successful passes through [`WorkerReporter`].
    #[doc(hidden)]
    pub fn assume_ready_for_test(&self) {
        self.inner.shutting_down.store(false, Ordering::Release);
        self.inner.supervisor_failed.store(false, Ordering::Release);
        for worker in WorkerName::ALL {
            let slot = self.slot(worker);
            slot.phase
                .store(WorkerPhase::Running as u8, Ordering::Release);
            // The sentinel is later than every real monotonic timestamp, so `age_at` remains
            // zero even in slow integration tests. `start` replaces it before real supervision.
            slot.last_heartbeat_millis
                .store(TEST_ALWAYS_FRESH, Ordering::Release);
            slot.last_success_millis
                .store(TEST_ALWAYS_FRESH, Ordering::Release);
            slot.consecutive_failures.store(0, Ordering::Release);
            slot.reported_unready.store(false, Ordering::Release);
        }
    }

    fn start(&self, worker: WorkerName) -> WorkerRunGuard {
        let slot = self.slot(worker);
        slot.last_success_millis
            .store(NEVER_RECORDED, Ordering::Release);
        slot.consecutive_failures.store(0, Ordering::Release);
        slot.reported_unready.store(false, Ordering::Release);
        slot.phase
            .store(WorkerPhase::Running as u8, Ordering::Release);
        self.record_heartbeat(worker, Instant::now());
        WorkerRunGuard {
            health: self.clone(),
            worker,
        }
    }

    fn begin_shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
        for worker in WorkerName::ALL {
            let slot = self.slot(worker);
            let phase = WorkerPhase::from_raw(slot.phase.load(Ordering::Acquire));
            if !matches!(phase, WorkerPhase::Failed | WorkerPhase::Stopped) {
                slot.phase
                    .store(WorkerPhase::Draining as u8, Ordering::Release);
            }
        }
    }

    fn mark_supervisor_failed(&self) {
        self.inner.supervisor_failed.store(true, Ordering::Release);
    }

    fn failed_count(&self) -> usize {
        WorkerName::ALL
            .iter()
            .filter(|worker| {
                WorkerPhase::from_raw(self.slot(**worker).phase.load(Ordering::Acquire))
                    == WorkerPhase::Failed
            })
            .count()
    }

    fn first_failed(&self) -> Option<WorkerName> {
        WorkerName::ALL.into_iter().find(|worker| {
            WorkerPhase::from_raw(self.slot(*worker).phase.load(Ordering::Acquire))
                == WorkerPhase::Failed
        })
    }

    fn finish(&self, worker: WorkerName) {
        let slot = self.slot(worker);
        let current = WorkerPhase::from_raw(slot.phase.load(Ordering::Acquire));
        if current == WorkerPhase::Failed {
            return;
        }
        let phase = if std::thread::panicking() || !self.inner.shutting_down.load(Ordering::Acquire)
        {
            WorkerPhase::Failed
        } else {
            WorkerPhase::Stopped
        };
        slot.phase.store(phase as u8, Ordering::Release);
    }

    fn record_heartbeat(&self, worker: WorkerName, now: Instant) {
        let timestamp = self.timestamp(now);
        self.slot(worker)
            .last_heartbeat_millis
            .store(timestamp, Ordering::Release);
    }

    fn record_success(&self, worker: WorkerName, now: Instant) {
        let timestamp = self.timestamp(now);
        let slot = self.slot(worker);
        slot.last_heartbeat_millis
            .store(timestamp, Ordering::Release);
        slot.last_success_millis.store(timestamp, Ordering::Release);
        slot.consecutive_failures.store(0, Ordering::Release);
        slot.reported_unready.store(false, Ordering::Release);
    }

    fn record_failure(&self, worker: WorkerName, now: Instant, immediate: bool) {
        self.record_heartbeat(worker, now);
        let slot = self.slot(worker);
        let _ = slot.consecutive_failures.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |failures| Some(failures.saturating_add(1)),
        );
        if immediate {
            slot.reported_unready.store(true, Ordering::Release);
        }
    }

    fn status_at(&self, worker: WorkerName, now: Instant) -> WorkerStatus {
        let slot = self.slot(worker);
        let phase = WorkerPhase::from_raw(slot.phase.load(Ordering::Acquire));
        let heartbeat = self.age_at(slot.last_heartbeat_millis.load(Ordering::Acquire), now);
        let success = self.age_at(slot.last_success_millis.load(Ordering::Acquire), now);
        let consecutive_failures = slot.consecutive_failures.load(Ordering::Acquire);
        let policy = worker.policy();
        let ready = phase == WorkerPhase::Running
            && heartbeat.is_some_and(|age| age <= policy.heartbeat_timeout)
            && success.is_some_and(|age| age <= policy.success_timeout)
            && consecutive_failures < policy.max_consecutive_failures
            && !slot.reported_unready.load(Ordering::Acquire);
        WorkerStatus {
            name: worker,
            phase,
            ready,
            last_heartbeat_age: heartbeat,
            last_success_age: success,
            consecutive_failures,
        }
    }

    fn slot(&self, worker: WorkerName) -> &WorkerSlot {
        &self.inner.slots[worker.index()]
    }

    fn timestamp(&self, now: Instant) -> u64 {
        let elapsed = now
            .checked_duration_since(self.inner.epoch)
            .unwrap_or_default();
        let millis = elapsed.as_millis().min(u128::from(u64::MAX - 1)) as u64;
        millis + 1
    }

    fn age_at(&self, timestamp: u64, now: Instant) -> Option<Duration> {
        if timestamp == NEVER_RECORDED {
            return None;
        }
        Some(Duration::from_millis(
            self.timestamp(now).saturating_sub(timestamp),
        ))
    }
}

impl Default for WorkerHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WorkerStatus {
    pub name: WorkerName,
    pub phase: WorkerPhase,
    pub ready: bool,
    pub last_heartbeat_age: Option<Duration>,
    pub last_success_age: Option<Duration>,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone)]
pub struct WorkerReadiness {
    pub ready: bool,
    pub workers: [WorkerStatus; WORKER_COUNT],
}

impl WorkerReadiness {
    pub fn unready_names(&self) -> Vec<&'static str> {
        self.workers
            .iter()
            .filter(|worker| !worker.ready)
            .map(|worker| worker.name.as_str())
            .collect()
    }
}

#[derive(Clone)]
pub struct WorkerReporter {
    health: WorkerHealth,
    worker: WorkerName,
}

impl WorkerReporter {
    pub fn heartbeat(&self) {
        self.health.record_heartbeat(self.worker, Instant::now());
    }

    pub fn success(&self) {
        self.health.record_success(self.worker, Instant::now());
    }

    pub fn retryable_failure(&self) {
        self.health
            .record_failure(self.worker, Instant::now(), false);
    }

    /// Immediately removes the worker from readiness while keeping it alive for recovery.
    /// A later successful pass clears this state. Key-sync safety policy can use this hook.
    pub fn report_unready(&self) {
        self.health
            .record_failure(self.worker, Instant::now(), true);
    }
}

struct WorkerRunGuard {
    health: WorkerHealth,
    worker: WorkerName,
}

impl Drop for WorkerRunGuard {
    fn drop(&mut self) {
        self.health.finish(self.worker);
    }
}

#[cfg(test)]
#[path = "workers_tests.rs"]
mod tests;
