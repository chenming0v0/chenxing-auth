//! Pure unit tests for the opt-in test DB timing helper.
//!
//! These never touch the process environment: every test injects its sink
//! explicitly through [`Timing::with_sink`], and the one file-backed test uses
//! a unique temp path that it removes afterwards.

use std::path::PathBuf;
use std::time::Duration;

use super::{
    Outcome, PHASE_BOOTSTRAP_CONNECTION, PHASE_DROP_CREATE_SCHEMA, PHASE_MIGRATE,
    PHASE_MIGRATION_APPLY, PHASE_MIGRATION_LOCK_WAIT, PHASE_POOL_CONNECT, PHASE_SEQUENCE_RESET,
    Timing,
};

const SINK: &str = "/tmp/chenxing-test-timing-placeholder.jsonl";

fn enabled_timing() -> Timing {
    Timing::with_sink(Some(PathBuf::from(SINK)))
}

/// Record every fixture phase with a deterministic zero so unit-generated
/// success events satisfy the same reporter contract as production records.
fn record_all_fixture_phases_zero(timing: &mut Timing) {
    for phase in [
        PHASE_BOOTSTRAP_CONNECTION,
        PHASE_DROP_CREATE_SCHEMA,
        PHASE_POOL_CONNECT,
        PHASE_MIGRATE,
        PHASE_SEQUENCE_RESET,
    ] {
        timing.record_zero(phase);
    }
}

fn parse(line: String) -> serde_json::Value {
    assert!(line.ends_with('\n'), "line must be newline terminated");
    serde_json::from_str(line.trim_end()).expect("event line must be valid JSON")
}

fn sorted_keys(object: &serde_json::Map<String, serde_json::Value>) -> Vec<&str> {
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn assert_finite_nonnegative(phases: &serde_json::Map<String, serde_json::Value>) {
    for (name, value) in phases {
        let millis = value
            .as_f64()
            .unwrap_or_else(|| panic!("phase {name} is not a number"));
        assert!(
            millis.is_finite() && millis >= 0.0,
            "phase {name} must be finite and nonnegative, got {millis}"
        );
    }
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chenxing-test-timing-{tag}-{}-{nanos}.jsonl",
        std::process::id()
    ));
    path
}

#[test]
fn fixture_line_matches_contract_schema() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_BOOTSTRAP_CONNECTION, Duration::from_millis(1));
    timing.record_elapsed(PHASE_DROP_CREATE_SCHEMA, Duration::from_millis(2));
    timing.record_elapsed(PHASE_POOL_CONNECT, Duration::from_millis(3));
    timing.record_elapsed(PHASE_MIGRATE, Duration::from_millis(4));
    timing.record_zero(PHASE_SEQUENCE_RESET);

    let line = timing
        .encode_fixture_line("api", "platform::api::case", Outcome::Ok)
        .expect("enabled timing must encode");
    assert!(!line.contains(SINK), "sink path must not leak");
    assert!(!line.contains("postgres"));
    assert!(!line.contains("://"));

    let event = parse(line);

    assert_eq!(
        sorted_keys(event.as_object().expect("object")),
        [
            "binary_name",
            "database_mode",
            "event",
            "outcome",
            "phases_ms",
            "pid",
            "test_identity",
            "version",
        ]
    );
    assert_eq!(event["version"], 1);
    assert_eq!(event["event"], "fixture");
    assert_eq!(event["binary_name"], "api");
    assert_eq!(event["test_identity"], "platform::api::case");
    assert_eq!(event["database_mode"], "schema");
    assert_eq!(event["outcome"], "ok");
    assert!(event["pid"].as_u64().is_some_and(|pid| pid > 0));

    let phases = event["phases_ms"].as_object().expect("phases object");
    assert_eq!(
        sorted_keys(phases),
        [
            "bootstrap_connection",
            "drop_create_schema",
            "migrate",
            "pool_connect",
            "sequence_reset",
        ]
    );
    assert_eq!(phases["sequence_reset"], 0.0);
    assert_finite_nonnegative(phases);
}

#[test]
fn migration_line_matches_contract_schema() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_MIGRATION_LOCK_WAIT, Duration::from_millis(5));
    timing.record_elapsed(PHASE_MIGRATION_APPLY, Duration::from_millis(6));

    let line = timing
        .encode_migration_line("platform-abc123", "platform::migration::case", Outcome::Ok)
        .expect("enabled timing must encode");
    let event = parse(line);

    assert_eq!(event["event"], "migration");
    assert_eq!(event["database_mode"], "schema");
    assert_eq!(event["outcome"], "ok");
    let phases = event["phases_ms"].as_object().expect("phases object");
    assert_eq!(
        sorted_keys(phases),
        ["migration_apply_ms", "migration_lock_wait_ms"]
    );
    assert_finite_nonnegative(phases);
}

#[test]
fn disabled_timing_does_no_work() {
    let timing = Timing::disabled();
    assert!(!timing.enabled());
    assert!(timing.phase_start().is_none());
    assert!(timing.encode_fixture_line("b", "i", Outcome::Ok).is_none());
    assert!(
        timing
            .encode_migration_line("b", "i", Outcome::Ok)
            .is_none()
    );

    let mut empty = Timing::with_sink(Some(PathBuf::from("")));
    assert!(!empty.enabled());
    empty.record_elapsed(PHASE_MIGRATE, Duration::from_millis(9));
    assert!(
        empty
            .encode_fixture_line("b", "i", Outcome::Error)
            .is_none(),
        "empty sink must stay disabled"
    );
}

#[test]
fn error_event_omits_phases_that_never_ran() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_BOOTSTRAP_CONNECTION, Duration::from_millis(1));

    let event = parse(
        timing
            .encode_fixture_line("api", "platform::api::case", Outcome::Error)
            .expect("enabled timing must encode"),
    );
    assert_eq!(event["outcome"], "error");
    let phases = event["phases_ms"].as_object().expect("phases object");
    assert!(phases.contains_key("bootstrap_connection"));
    for absent in [
        "drop_create_schema",
        "pool_connect",
        "migrate",
        "sequence_reset",
    ] {
        assert!(
            !phases.contains_key(absent),
            "unexecuted phase {absent} must be omitted"
        );
    }
    assert_finite_nonnegative(phases);
}

#[test]
fn migration_connection_acquire_failure_has_no_phases() {
    let timing = enabled_timing();
    // Only a failed pool-connection acquire leaves the event without samples.
    let event = parse(
        timing
            .encode_migration_line("platform", "platform::migration::case", Outcome::Error)
            .expect("enabled timing must encode"),
    );
    assert_eq!(event["outcome"], "error");
    let phases = event["phases_ms"].as_object().expect("phases object");
    assert!(phases.is_empty());
}

#[test]
fn migration_lock_failure_records_wait_without_apply() {
    let mut timing = enabled_timing();
    // A failed Migrate::lock attempt still consumed wait time and is recorded;
    // the apply phase was never reached and must be absent.
    timing.record_elapsed(PHASE_MIGRATION_LOCK_WAIT, Duration::from_millis(3));

    let event = parse(
        timing
            .encode_migration_line("platform", "platform::migration::case", Outcome::Error)
            .expect("enabled timing must encode"),
    );
    let phases = event["phases_ms"].as_object().expect("phases object");
    assert!(phases.contains_key("migration_lock_wait_ms"));
    assert!(!phases.contains_key("migration_apply_ms"));
}

#[test]
fn migration_apply_omitted_when_never_reached() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_MIGRATION_LOCK_WAIT, Duration::from_millis(2));

    let event = parse(
        timing
            .encode_migration_line("platform", "platform::migration::case", Outcome::Error)
            .expect("enabled timing must encode"),
    );
    let phases = event["phases_ms"].as_object().expect("phases object");
    assert!(phases.contains_key("migration_lock_wait_ms"));
    assert!(!phases.contains_key("migration_apply_ms"));
}

#[tokio::test]
async fn successful_append_writes_exactly_one_json_line() {
    let path = unique_temp_path("single");
    let mut timing = Timing::with_sink(Some(path.clone()));
    record_all_fixture_phases_zero(&mut timing);
    timing
        .emit_fixture("api", "platform::api::case", Outcome::Ok)
        .await;

    let contents = std::fs::read_to_string(&path).expect("diagnostics file must exist");
    std::fs::remove_file(&path).ok();

    assert_eq!(contents.lines().count(), 1);
    assert!(contents.ends_with('\n'));
    let event = parse(contents);
    assert_eq!(event["event"], "fixture");
    assert_eq!(event["outcome"], "ok");
    assert_eq!(
        sorted_keys(event["phases_ms"].as_object().expect("phases object")),
        [
            "bootstrap_connection",
            "drop_create_schema",
            "migrate",
            "pool_connect",
            "sequence_reset",
        ]
    );
}

#[tokio::test]
async fn concurrent_appends_produce_one_line_per_event() {
    let path = unique_temp_path("concurrent");

    let mut handles = Vec::new();
    for index in 0..8 {
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let mut timing = Timing::with_sink(Some(path));
            record_all_fixture_phases_zero(&mut timing);
            timing
                .emit_fixture(
                    &format!("binary_{index}"),
                    "platform::concurrent",
                    Outcome::Ok,
                )
                .await;
        }));
    }
    for handle in handles {
        handle.await.expect("diagnostic write task must not panic");
    }

    let contents = std::fs::read_to_string(&path).expect("diagnostics file must exist");
    std::fs::remove_file(&path).ok();

    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 8);
    for line in lines {
        let event: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        assert_eq!(event["event"], "fixture");
        assert_eq!(event["outcome"], "ok");
        let phases = event["phases_ms"].as_object().expect("phases object");
        assert_eq!(phases.len(), 5);
        assert_finite_nonnegative(phases);
    }
}

#[tokio::test]
async fn invalid_sink_is_best_effort_and_leaves_state_usable() {
    let mut timing = Timing::with_sink(Some(PathBuf::from(
        "/nonexistent-chenxing-test-dir/timing.jsonl",
    )));
    record_all_fixture_phases_zero(&mut timing);

    // Must resolve normally: a broken sink cannot panic or surface an error.
    timing
        .emit_fixture("api", "platform::api::case", Outcome::Ok)
        .await;

    let event = parse(
        timing
            .encode_fixture_line("api", "platform::api::case", Outcome::Ok)
            .expect("timing stays enabled after a failed write"),
    );
    assert!(event["phases_ms"]["migrate"].as_f64().is_some());
}
