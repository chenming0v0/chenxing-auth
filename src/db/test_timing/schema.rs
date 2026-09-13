//! JSON line encoding for the opt-in test DB timing diagnostics.
//!
//! Two schema generations share this sink:
//!
//! - v1 (`database_mode = "schema"`): the original `fixture` / `migration`
//!   events emitted by the schema-isolated integration fixtures.
//! - v2 (`database_mode = "template"`): the stage 1 template lifecycle,
//!   `fixture` (template clone) and `template_prepare` (template build) events.
//!
//! The reporter treats every `(version, event)` pair as its own contract. Do
//! not loosen one generation to accommodate the other: old stage 0 artifacts
//! must keep parsing exactly as before.

use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value};

pub(super) const EVENT_VERSION_V1: u32 = 1;
pub(super) const EVENT_VERSION_V2: u32 = 2;

pub(super) const FIXTURE_EVENT: &str = "fixture";
pub(super) const MIGRATION_EVENT: &str = "migration";
pub(super) const TEMPLATE_PREPARE_EVENT: &str = "template_prepare";

pub(super) const DATABASE_MODE_SCHEMA: &str = "schema";
pub(super) const DATABASE_MODE_TEMPLATE: &str = "template";

#[derive(Serialize)]
struct EventV1<'a> {
    version: u32,
    event: &'static str,
    binary_name: &'a str,
    test_identity: &'a str,
    pid: u32,
    database_mode: &'static str,
    outcome: &'static str,
    phases_ms: Map<String, Value>,
}

#[derive(Serialize)]
struct EventV2<'a> {
    version: u32,
    event: &'static str,
    binary_name: &'a str,
    test_identity: &'a str,
    pid: u32,
    database_mode: &'static str,
    outcome: &'static str,
    phases_ms: Map<String, Value>,
    // `template_prepare` has no overall timer and must omit the key entirely;
    // `fixture` (template) always carries a finite nonnegative value.
    #[serde(skip_serializing_if = "Option::is_none")]
    fixture_total_ms: Option<f64>,
}

pub(super) fn encode_event_v1(
    event: &'static str,
    binary_name: &str,
    test_identity: &str,
    outcome: &'static str,
    phases_ms: &Map<String, Value>,
) -> Option<String> {
    encode(&EventV1 {
        version: EVENT_VERSION_V1,
        event,
        binary_name,
        test_identity,
        pid: std::process::id(),
        database_mode: DATABASE_MODE_SCHEMA,
        outcome,
        phases_ms: phases_ms.clone(),
    })
}

pub(super) fn encode_event_v2(
    event: &'static str,
    database_mode: &'static str,
    binary_name: &str,
    test_identity: &str,
    outcome: &'static str,
    phases_ms: &Map<String, Value>,
    fixture_total_ms: Option<f64>,
) -> Option<String> {
    encode(&EventV2 {
        version: EVENT_VERSION_V2,
        event,
        binary_name,
        test_identity,
        pid: std::process::id(),
        database_mode,
        outcome,
        phases_ms: phases_ms.clone(),
        fixture_total_ms,
    })
}

fn encode<T: Serialize>(event: &T) -> Option<String> {
    let mut line = serde_json::to_string(event).ok()?;
    line.push('\n');
    Some(line)
}

/// Overall template-fixture duration.
///
/// The caller captures `start` before any configuration is parsed, so the value
/// covers the disjoint stage samples plus the unmeasured interstage overhead.
///
/// A missing timer is not a licence to sum the recorded stage samples: that sum
/// omits interstage overhead and, because a v2 `fixture` event carries only
/// `fixture_total_ms`, the reporter would present it as the actual overall
/// duration. Callers with an enabled sink always hold a real timer, so a
/// missing `start` means the measurement is unavailable and the event must not
/// be emitted.
pub(super) fn fixture_total_ms(start: Option<Instant>) -> Option<f64> {
    Some(millis(start?.elapsed()))
}

pub(super) fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
