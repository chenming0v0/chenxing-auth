//! Opt-in diagnostic timing for test database fixtures (issue #710, stage 0).
//!
//! This is internal test plumbing shared by the integration fixture
//! (`tests/support/db_isolation.rs`) and the production migration runner. It is
//! dormant unless `CHENXING_TEST_DB_TIMING_FILE` names a non-empty file: with
//! the variable unset or empty there is no clock read, serialization, or file
//! access beyond the single environment lookup.
//!
//! When enabled, each completed fixture or migration invocation appends one
//! complete JSON object followed by `\n` with a single `O_APPEND` write attempt
//! on a blocking thread. A short write is rejected rather than split across
//! appends. Diagnostic failures are best effort: they never change the database
//! result, panic, or log the sink path, error, or URL.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value, json};

mod migration;
pub use migration::MigrationTiming;

/// Environment variable that opts a test process into timing diagnostics.
///
/// Unset or empty disables the module completely.
#[doc(hidden)]
pub const TIMING_FILE_ENV: &str = "CHENXING_TEST_DB_TIMING_FILE";

const EVENT_VERSION: u32 = 1;
const FIXTURE_EVENT: &str = "fixture";
const MIGRATION_EVENT: &str = "migration";
const DATABASE_MODE_SCHEMA: &str = "schema";

// Fixture phase keys (issue #710 stage 0 contract).
#[doc(hidden)]
pub const PHASE_BOOTSTRAP_CONNECTION: &str = "bootstrap_connection";
#[doc(hidden)]
pub const PHASE_DROP_CREATE_SCHEMA: &str = "drop_create_schema";
#[doc(hidden)]
pub const PHASE_POOL_CONNECT: &str = "pool_connect";
#[doc(hidden)]
pub const PHASE_MIGRATE: &str = "migrate";
#[doc(hidden)]
pub const PHASE_SEQUENCE_RESET: &str = "sequence_reset";

// Migration phase keys. The `_ms` suffix is part of the JSON contract here,
// unlike the fixture phases.
#[doc(hidden)]
pub const PHASE_MIGRATION_LOCK_WAIT: &str = "migration_lock_wait_ms";
#[doc(hidden)]
pub const PHASE_MIGRATION_APPLY: &str = "migration_apply_ms";

/// Overall outcome of one instrumented invocation.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Error,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Phase accumulator plus resolved sink for one fixture or migration invocation.
#[doc(hidden)]
#[derive(Debug)]
pub struct Timing {
    sink: Option<PathBuf>,
    phases: Map<String, Value>,
}

impl Timing {
    /// Disabled accumulator: every method is a no-op.
    pub fn disabled() -> Self {
        Self {
            sink: None,
            phases: Map::new(),
        }
    }

    /// Resolve the sink from `CHENXING_TEST_DB_TIMING_FILE`.
    pub fn from_env() -> Self {
        let sink = std::env::var(TIMING_FILE_ENV)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self::with_sink(sink)
    }

    /// Explicit sink injection used by tests; an empty path means disabled.
    pub fn with_sink(sink: Option<PathBuf>) -> Self {
        let sink = sink.filter(|path| !path.as_os_str().is_empty());
        Self {
            sink,
            phases: Map::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.sink.is_some()
    }

    /// Start a phase timer, or `None` when diagnostics are disabled.
    pub fn phase_start(&self) -> Option<Instant> {
        self.enabled().then(Instant::now)
    }

    /// Record `phase` from a [`Self::phase_start`] token.
    pub fn record(&mut self, phase: &'static str, start: Option<Instant>) {
        if let Some(start) = start {
            self.record_elapsed(phase, start.elapsed());
        }
    }

    /// Record an explicit duration; used by tests and by the internal timer.
    pub fn record_elapsed(&mut self, phase: &'static str, elapsed: Duration) {
        if self.sink.is_none() {
            return;
        }
        self.phases.insert(phase.to_owned(), json!(millis(elapsed)));
    }

    /// Record a zero duration for an intentionally skipped phase.
    pub fn record_zero(&mut self, phase: &'static str) {
        if self.sink.is_none() {
            return;
        }
        self.phases.insert(phase.to_owned(), json!(0.0));
    }

    /// Serialize one fixture event line, or `None` when disabled.
    pub fn encode_fixture_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) -> Option<String> {
        self.sink.as_ref()?;
        encode_event(
            FIXTURE_EVENT,
            binary_name,
            test_identity,
            outcome,
            &self.phases,
        )
    }

    /// Serialize one migration event line, or `None` when disabled.
    pub fn encode_migration_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) -> Option<String> {
        self.sink.as_ref()?;
        encode_event(
            MIGRATION_EVENT,
            binary_name,
            test_identity,
            outcome,
            &self.phases,
        )
    }

    /// Append one fixture event. Failures are swallowed.
    pub async fn emit_fixture(&self, binary_name: &str, test_identity: &str, outcome: Outcome) {
        if let Some(line) = self.encode_fixture_line(binary_name, test_identity, outcome) {
            self.append(line).await;
        }
    }

    /// Append one migration event. Failures are swallowed.
    pub async fn emit_migration(&self, binary_name: &str, test_identity: &str, outcome: Outcome) {
        if let Some(line) = self.encode_migration_line(binary_name, test_identity, outcome) {
            self.append(line).await;
        }
    }

    async fn append(&self, line: String) {
        let Some(sink) = self.sink.clone() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            warn_write_failed();
            return;
        }
        let joined =
            tokio::task::spawn_blocking(move || append_blocking(&sink, line.as_bytes())).await;
        if !matches!(joined, Ok(Ok(()))) {
            warn_write_failed();
        }
    }
}

#[derive(Serialize)]
struct Event<'a> {
    version: u32,
    event: &'static str,
    binary_name: &'a str,
    test_identity: &'a str,
    pid: u32,
    database_mode: &'static str,
    outcome: &'static str,
    phases_ms: Map<String, Value>,
}

fn encode_event(
    event: &'static str,
    binary_name: &str,
    test_identity: &str,
    outcome: Outcome,
    phases_ms: &Map<String, Value>,
) -> Option<String> {
    let mut line = serde_json::to_string(&Event {
        version: EVENT_VERSION,
        event,
        binary_name,
        test_identity,
        pid: std::process::id(),
        database_mode: DATABASE_MODE_SCHEMA,
        outcome: outcome.as_str(),
        phases_ms: phases_ms.clone(),
    })
    .ok()?;
    line.push('\n');
    Some(line)
}

fn append_blocking(sink: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sink)?;
    // One complete-record write attempt. A short write would split the record
    // across multiple appends and break the one-line-per-event contract, so it
    // is rejected instead of appending the remainder; a reporter then fails
    // closed on the truncated evidence. `Interrupted` means no bytes were
    // written, so retrying the full buffer stays atomic.
    loop {
        match file.write(bytes) {
            Ok(written) if written == bytes.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short append",
                ));
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn warn_write_failed() {
    tracing::warn!("test DB timing diagnostics could not be appended");
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests;
