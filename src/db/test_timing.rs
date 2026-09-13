//! Opt-in diagnostic timing for test database fixtures (issue #710).
//!
//! This is internal test plumbing shared by the integration fixture
//! (`tests/support/db_isolation.rs`), the template lifecycle example, and the
//! production migration runner. It is dormant unless
//! `CHENXING_TEST_DB_TIMING_FILE` names a non-empty file: with the variable
//! unset or empty there is no clock read, serialization, or file access beyond
//! the single environment lookup.
//!
//! When enabled, each completed fixture or migration invocation appends one
//! complete JSON object followed by `\n` with a single `O_APPEND` write attempt
//! on a blocking thread. A short write is rejected rather than split across
//! appends. Diagnostic failures are best effort: they never change the database
//! result, panic, or log the sink path, error, or URL.
//!
//! Stage 1 adds the template lifecycle (`database_mode = "template"`):
//!
//! - `emit_template_fixture` writes one v2 `fixture` event for a template
//!   clone, including the overall `fixture_total_ms` timer that starts before
//!   any configuration is parsed.
//! - `emit_template_prepare` writes one v2 `template_prepare` event for the
//!   template build. Its `template_prepare_ms` already contains the inner
//!   migration run, so [`without_migration_diagnostics`] suppresses the nested
//!   `db::migrate` migration event. Emitted migration counts therefore do not
//!   represent every migrate call.

use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

mod emit;
mod migration;
mod schema;
pub use migration::MigrationTiming;

/// Environment variable that opts a test process into timing diagnostics.
///
/// Unset or empty disables the module completely.
#[doc(hidden)]
pub const TIMING_FILE_ENV: &str = "CHENXING_TEST_DB_TIMING_FILE";

// Fixture phase keys (issue #710 stage 0 schema contract).
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

// Template fixture phase keys (issue #710 stage 1 v2 contract). `migrate` and
// `drop_create_schema` do not apply to a clone from a prepared template.
#[doc(hidden)]
pub const PHASE_DATABASE_CLONE: &str = "database_clone_ms";
#[doc(hidden)]
pub const PHASE_TEMPLATE_PREPARE: &str = "template_prepare_ms";

// Migration phase keys. The `_ms` suffix is part of the JSON contract here,
// unlike the schema fixture phases.
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

tokio::task_local! {
    /// Marks the current task tree as building a template database. The inner
    /// `db::migrate` diagnostic event is redundant there because
    /// `template_prepare_ms` already measures it.
    static MIGRATION_DIAGNOSTICS_SUPPRESSED: ();
}

/// True when the current task is inside [`without_migration_diagnostics`].
#[doc(hidden)]
pub fn migration_diagnostics_suppressed() -> bool {
    MIGRATION_DIAGNOSTICS_SUPPRESSED.try_with(|_| ()).is_ok()
}

/// Run `future` with nested migration diagnostics suppressed.
///
/// This is task-local scope only: no process environment is read or mutated,
/// migration semantics and error precedence are untouched, and after the
/// future resolves (normally or with an error) the suppression is gone. A task
/// spawned inside the scope does not inherit it.
pub async fn without_migration_diagnostics<F: Future>(future: F) -> F::Output {
    MIGRATION_DIAGNOSTICS_SUPPRESSED.scope((), future).await
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

    /// Serialize one v1 schema fixture event line, or `None` when disabled.
    pub fn encode_fixture_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) -> Option<String> {
        self.sink.as_ref()?;
        schema::encode_event_v1(
            schema::FIXTURE_EVENT,
            binary_name,
            test_identity,
            outcome.as_str(),
            &self.phases,
        )
    }

    /// Serialize one v1 schema migration event line, or `None` when disabled.
    pub fn encode_migration_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) -> Option<String> {
        self.sink.as_ref()?;
        schema::encode_event_v1(
            schema::MIGRATION_EVENT,
            binary_name,
            test_identity,
            outcome.as_str(),
            &self.phases,
        )
    }

    /// Serialize one v2 template fixture event, including `fixture_total_ms`.
    ///
    /// Returns `None` when disabled or when no wrapper `fixture_start` was
    /// captured: without a real timer the whole-fixture duration is unknown, so
    /// the event is refused rather than emitting a phase-sum estimate.
    pub fn encode_template_fixture_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
        fixture_start: Option<Instant>,
    ) -> Option<String> {
        self.sink.as_ref()?;
        let total = schema::fixture_total_ms(fixture_start)?;
        schema::encode_event_v2(
            schema::FIXTURE_EVENT,
            schema::DATABASE_MODE_TEMPLATE,
            binary_name,
            test_identity,
            outcome.as_str(),
            &self.phases,
            Some(total),
        )
    }

    /// Serialize one v2 template preparation event. It has no overall timer.
    pub fn encode_template_prepare_line(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) -> Option<String> {
        self.sink.as_ref()?;
        schema::encode_event_v2(
            schema::TEMPLATE_PREPARE_EVENT,
            schema::DATABASE_MODE_TEMPLATE,
            binary_name,
            test_identity,
            outcome.as_str(),
            &self.phases,
            None,
        )
    }
}

fn millis(duration: Duration) -> f64 {
    schema::millis(duration)
}

#[cfg(test)]
mod template_tests;
#[cfg(test)]
mod tests;
