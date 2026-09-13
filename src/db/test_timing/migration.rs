//! Migration-side timing hook for the production migration runner.
//!
//! Split from [`super`] so the fixture accumulator stays small. The hook
//! captures the event metadata before the first await: an async worker thread
//! may be reused for a different test after a suspension point, so the process
//! environment and current thread are not reliable once a future yields.

use std::time::Instant;

use super::{Outcome, Timing};

/// Migration hook: captures its metadata before the first await so a reused
/// async worker thread can never misattribute the event.
#[doc(hidden)]
pub struct MigrationTiming {
    timing: Timing,
    metadata: Option<(String, String)>,
}

impl MigrationTiming {
    pub fn from_env() -> Self {
        // Template preparation measures the whole build in `template_prepare_ms`
        // and suppresses the nested migration event. This is a task-local scope
        // check only: the environment is never read or mutated differently, and
        // outside the scope behavior is identical.
        if super::migration_diagnostics_suppressed() {
            return Self {
                timing: Timing::disabled(),
                metadata: None,
            };
        }
        let timing = Timing::from_env();
        let metadata = timing
            .enabled()
            .then(|| (current_binary_name(), current_test_identity()));
        Self { timing, metadata }
    }

    pub fn enabled(&self) -> bool {
        self.timing.enabled()
    }

    pub fn phase_start(&self) -> Option<Instant> {
        self.timing.phase_start()
    }

    pub fn record(&mut self, phase: &'static str, start: Option<Instant>) {
        self.timing.record(phase, start);
    }

    pub async fn emit(&self, outcome: Outcome) {
        if let Some((binary_name, test_identity)) = &self.metadata {
            self.timing
                .emit_migration(binary_name, test_identity, outcome)
                .await;
        }
    }
}

/// Basename of the running test executable, the contract's `binary_name`.
fn current_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "unknown-test-binary".to_owned())
}

/// `NEXTEST_TEST_NAME`, falling back to the current thread name or id.
fn current_test_identity() -> String {
    if let Some(name) = std::env::var("NEXTEST_TEST_NAME")
        .ok()
        .filter(|name| !name.is_empty())
    {
        return name;
    }

    let thread = std::thread::current();
    thread
        .name()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{:?}", thread.id()))
}
