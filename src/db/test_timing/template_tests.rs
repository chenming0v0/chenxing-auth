//! Pure unit tests for the stage 1 template timing contract.
//!
//! Like the v1 tests, these never touch the process environment: sinks are
//! injected explicitly. The suppression tests exercise task-local scope only,
//! so they stay deterministic whether or not `CHENXING_TEST_DB_TIMING_FILE` is
//! set by the outer test runner.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{
    MigrationTiming, Outcome, PHASE_BOOTSTRAP_CONNECTION, PHASE_DATABASE_CLONE, PHASE_POOL_CONNECT,
    PHASE_SEQUENCE_RESET, PHASE_TEMPLATE_PREPARE, Timing, migration_diagnostics_suppressed,
    without_migration_diagnostics,
};

const SINK: &str = "/tmp/chenxing-test-timing-template-placeholder.jsonl";

fn enabled_timing() -> Timing {
    Timing::with_sink(Some(PathBuf::from(SINK)))
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

fn assert_finite_nonnegative(value: &serde_json::Value, label: &str) {
    let millis = value
        .as_f64()
        .unwrap_or_else(|| panic!("{label} is not a number"));
    assert!(
        millis.is_finite() && millis >= 0.0,
        "{label} must be finite and nonnegative, got {millis}"
    );
}

fn record_template_fixture_phases(timing: &mut Timing) {
    timing.record_elapsed(PHASE_BOOTSTRAP_CONNECTION, Duration::from_millis(1));
    timing.record_elapsed(PHASE_DATABASE_CLONE, Duration::from_millis(2));
    timing.record_elapsed(PHASE_POOL_CONNECT, Duration::from_millis(3));
    timing.record_zero(PHASE_SEQUENCE_RESET);
}

#[test]
fn template_fixture_line_matches_v2_contract_schema() {
    let mut timing = enabled_timing();
    record_template_fixture_phases(&mut timing);

    let line = timing
        .encode_template_fixture_line(
            "integration_storage",
            "integration::repository::case",
            Outcome::Ok,
            Some(Instant::now()),
        )
        .expect("enabled timing must encode");
    assert!(!line.contains(SINK), "sink path must not leak");

    let event = parse(line);
    assert_eq!(
        sorted_keys(event.as_object().expect("object")),
        [
            "binary_name",
            "database_mode",
            "event",
            "fixture_total_ms",
            "outcome",
            "phases_ms",
            "pid",
            "test_identity",
            "version",
        ]
    );
    assert_eq!(event["version"], 2);
    assert_eq!(event["event"], "fixture");
    assert_eq!(event["database_mode"], "template");
    assert_eq!(event["outcome"], "ok");
    assert_finite_nonnegative(&event["fixture_total_ms"], "fixture_total_ms");

    let phases = event["phases_ms"].as_object().expect("phases object");
    assert_eq!(
        sorted_keys(phases),
        [
            "bootstrap_connection",
            "database_clone_ms",
            "pool_connect",
            "sequence_reset",
        ]
    );
    assert_eq!(phases["sequence_reset"], 0.0);
    for (name, value) in phases {
        assert_finite_nonnegative(value, name);
    }
}

#[test]
fn template_fixture_error_keeps_only_reached_phases() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_BOOTSTRAP_CONNECTION, Duration::from_millis(1));

    let event = parse(
        timing
            .encode_template_fixture_line(
                "integration_storage",
                "integration::repository::case",
                Outcome::Error,
                Some(Instant::now()),
            )
            .expect("enabled timing must encode"),
    );
    assert_eq!(event["outcome"], "error");
    assert_finite_nonnegative(&event["fixture_total_ms"], "fixture_total_ms");

    let phases = event["phases_ms"].as_object().expect("phases object");
    assert!(phases.contains_key("bootstrap_connection"));
    for absent in ["database_clone_ms", "pool_connect", "sequence_reset"] {
        assert!(
            !phases.contains_key(absent),
            "unreached phase {absent} must be omitted"
        );
    }
}

#[test]
fn template_prepare_line_has_one_phase_and_no_total() {
    let mut timing = enabled_timing();
    timing.record_elapsed(PHASE_TEMPLATE_PREPARE, Duration::from_millis(42));

    let event = parse(
        timing
            .encode_template_prepare_line("test_database", "prepare", Outcome::Ok)
            .expect("enabled timing must encode"),
    );
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
        ],
        "template_prepare must not carry fixture_total_ms"
    );
    assert_eq!(event["version"], 2);
    assert_eq!(event["event"], "template_prepare");
    assert_eq!(event["database_mode"], "template");
    assert_eq!(event["outcome"], "ok");

    let phases = event["phases_ms"].as_object().expect("phases object");
    assert_eq!(sorted_keys(phases), ["template_prepare_ms"]);
    assert_finite_nonnegative(&phases["template_prepare_ms"], "template_prepare_ms");
}

#[test]
fn template_prepare_error_may_have_empty_phases() {
    let timing = enabled_timing();
    let event = parse(
        timing
            .encode_template_prepare_line("test_database", "prepare", Outcome::Error)
            .expect("enabled timing must encode"),
    );
    assert_eq!(event["outcome"], "error");
    assert!(
        event["phases_ms"]
            .as_object()
            .expect("phases object")
            .is_empty()
    );
    assert!(event.get("fixture_total_ms").is_none());
}

#[test]
fn enabled_template_fixture_without_wrapper_timer_refuses_to_emit() {
    let mut timing = enabled_timing();
    record_template_fixture_phases(&mut timing);

    // Phase samples exist (they would sum to 6 ms), but without the wrapper
    // timer the whole-fixture duration is unknown. Refuse rather than emit a
    // phase-sum value that the reporter would present as the actual total.
    assert!(
        timing
            .encode_template_fixture_line(
                "integration_storage",
                "integration::repository::case",
                Outcome::Ok,
                None,
            )
            .is_none(),
        "a missing wrapper timer must not be replaced by a phase-sum estimate"
    );

    // Disabled timing still emits nothing and never reads the clock.
    assert!(
        Timing::disabled()
            .encode_template_fixture_line("b", "i", Outcome::Ok, None)
            .is_none()
    );
}

#[test]
fn disabled_timing_emits_no_template_events() {
    let timing = Timing::disabled();
    assert!(
        timing
            .encode_template_fixture_line("b", "i", Outcome::Ok, None)
            .is_none()
    );
    assert!(
        timing
            .encode_template_prepare_line("b", "i", Outcome::Ok)
            .is_none()
    );
}

#[test]
fn suppression_flag_is_off_outside_scope() {
    assert!(!migration_diagnostics_suppressed());
}

#[tokio::test]
async fn suppression_scope_is_nested() {
    without_migration_diagnostics(async {
        assert!(migration_diagnostics_suppressed());
        without_migration_diagnostics(async {
            assert!(migration_diagnostics_suppressed());
        })
        .await;
        assert!(
            migration_diagnostics_suppressed(),
            "outer scope must survive the inner one"
        );
    })
    .await;
    assert!(!migration_diagnostics_suppressed());
}

#[tokio::test]
async fn suppression_scope_exits_after_error() {
    let result: Result<(), &str> = without_migration_diagnostics(async { Err("boom") }).await;
    assert_eq!(result, Err("boom"));
    assert!(!migration_diagnostics_suppressed());
}

#[tokio::test]
async fn suppression_does_not_cross_spawned_tasks() {
    without_migration_diagnostics(async {
        assert!(migration_diagnostics_suppressed());
        let handle = tokio::spawn(async { migration_diagnostics_suppressed() });
        assert!(
            !handle.await.expect("spawned task must not panic"),
            "a spawned task must not inherit the suppression scope"
        );
    })
    .await;
}

#[tokio::test]
async fn migration_timing_is_disabled_inside_suppression_scope() {
    without_migration_diagnostics(async {
        assert!(!MigrationTiming::from_env().enabled());
    })
    .await;
}
