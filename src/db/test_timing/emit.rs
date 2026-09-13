//! Blocking append path and async emit wrappers for [`super::Timing`].
//!
//! Split from the schema/validation module so the event contract stays small.
//! Every method here is best effort: a diagnostic failure must never change the
//! database result or surface the sink path, error, or URL.

use std::io::Write;
use std::path::Path;
use std::time::Instant;

use super::{Outcome, Timing};

impl Timing {
    /// Append one v1 fixture event. Failures are swallowed.
    pub async fn emit_fixture(&self, binary_name: &str, test_identity: &str, outcome: Outcome) {
        if let Some(line) = self.encode_fixture_line(binary_name, test_identity, outcome) {
            self.append(line).await;
        }
    }

    /// Append one v1 migration event. Failures are swallowed.
    pub async fn emit_migration(&self, binary_name: &str, test_identity: &str, outcome: Outcome) {
        if let Some(line) = self.encode_migration_line(binary_name, test_identity, outcome) {
            self.append(line).await;
        }
    }

    /// Append one v2 template fixture event. Failures are swallowed.
    pub async fn emit_template_fixture(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
        fixture_start: Option<Instant>,
    ) {
        if let Some(line) =
            self.encode_template_fixture_line(binary_name, test_identity, outcome, fixture_start)
        {
            self.append(line).await;
        }
    }

    /// Append one v2 template preparation event. Failures are swallowed.
    pub async fn emit_template_prepare(
        &self,
        binary_name: &str,
        test_identity: &str,
        outcome: Outcome,
    ) {
        if let Some(line) = self.encode_template_prepare_line(binary_name, test_identity, outcome) {
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
