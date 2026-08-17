use std::{future::Future, time::Duration};

use tokio::{sync::watch, task::JoinSet};

use super::{WorkerHealth, WorkerName, WorkerReporter};

pub const WORKER_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WorkerContext {
    reporter: WorkerReporter,
    shutdown: watch::Receiver<bool>,
}

impl WorkerContext {
    pub fn reporter(&self) -> &WorkerReporter {
        &self.reporter
    }

    pub fn shutdown_requested(&self) -> bool {
        *self.shutdown.borrow()
    }

    pub async fn wait_for_shutdown(&mut self) {
        if self.shutdown_requested() {
            return;
        }
        while self.shutdown.changed().await.is_ok() {
            if self.shutdown_requested() {
                return;
            }
        }
    }

    /// Returns `true` when shutdown interrupted the wait.
    pub async fn sleep_or_shutdown(&mut self, duration: Duration) -> bool {
        if self.shutdown_requested() {
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(duration) => false,
            _ = self.wait_for_shutdown() => true,
        }
    }
}

pub struct WorkerSupervisor {
    health: WorkerHealth,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<WorkerName>,
}

impl WorkerSupervisor {
    pub fn new(health: WorkerHealth) -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            health,
            shutdown,
            tasks: JoinSet::new(),
        }
    }

    pub fn spawn<F, Fut>(&mut self, worker: WorkerName, task: F)
    where
        F: FnOnce(WorkerContext) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let guard = self.health.start(worker);
        let context = WorkerContext {
            reporter: self.health.reporter(worker),
            shutdown: self.shutdown.subscribe(),
        };
        self.tasks.spawn(async move {
            let _guard = guard;
            task(context).await;
            worker
        });
    }

    pub async fn wait_for_failure(&mut self) -> WorkerFailure {
        let failure = match self.tasks.join_next().await {
            Some(Ok(worker)) => WorkerFailure::Returned(worker),
            Some(Err(source)) => match self.health.first_failed() {
                Some(worker) => WorkerFailure::Task { worker, source },
                None => WorkerFailure::UnknownTask(source),
            },
            None => WorkerFailure::Empty,
        };
        self.health.mark_supervisor_failed();
        failure
    }

    pub fn begin_shutdown(&self) {
        self.health.begin_shutdown();
        let _ = self.shutdown.send(true);
    }

    pub async fn drain(&mut self, timeout: Duration) -> Result<(), WorkerDrainError> {
        self.begin_shutdown();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut task_failures = 0usize;
        while !self.tasks.is_empty() {
            match tokio::time::timeout_at(deadline, self.tasks.join_next()).await {
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(error))) => {
                    task_failures += 1;
                    tracing::error!(error = %error, "critical worker failed while draining");
                }
                Ok(None) => break,
                Err(_) => {
                    let aborted = self.tasks.len();
                    self.tasks.abort_all();
                    while self.tasks.join_next().await.is_some() {}
                    return Err(WorkerDrainError::TimedOut { aborted });
                }
            }
        }
        let failed = task_failures.max(self.health.failed_count());
        if failed > 0 {
            return Err(WorkerDrainError::Failed { workers: failed });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerFailure {
    #[error("critical worker {0} returned unexpectedly")]
    Returned(WorkerName),
    #[error("critical worker {worker} task failed: {source}")]
    Task {
        worker: WorkerName,
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("critical worker task failed before its identity could be resolved: {0}")]
    UnknownTask(#[source] tokio::task::JoinError),
    #[error("critical worker supervisor has no running tasks")]
    Empty,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerDrainError {
    #[error("{workers} critical worker(s) failed during shutdown")]
    Failed { workers: usize },
    #[error("critical worker drain timed out; aborted {aborted} worker(s)")]
    TimedOut { aborted: usize },
}
