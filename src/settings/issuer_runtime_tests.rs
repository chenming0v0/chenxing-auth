use std::{
    sync::{Arc, Barrier},
    thread,
};
use time::OffsetDateTime;

use super::{
    issuer::{IssuerRecord, RawIssuerRecord},
    issuer_runtime::{IssuerRuntime, IssuerRuntimeState, SystemPhase},
};
use crate::{config::Config, users::domain::INITIAL_OWNER_ID};

fn config() -> Config {
    Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned(),
        "redis://127.0.0.1:6379".to_owned(),
        3600,
    )
    .expect("config")
}

fn raw(value: Option<&str>, generation: i64) -> RawIssuerRecord {
    RawIssuerRecord {
        value: value.map(str::to_owned),
        generation,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn record(value: &str, generation: i64) -> IssuerRecord {
    IssuerRecord {
        value: value.to_owned(),
        generation,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[test]
fn raw_persistence_distinguishes_absence_pending_invalid_and_ready() {
    let config = config();
    let awaiting = IssuerRuntime::new_from_raw(&config, None);
    assert!(matches!(
        awaiting.state().as_ref(),
        IssuerRuntimeState::AwaitingIssuer
    ));
    assert!(awaiting.is_awaiting_configuration());

    for value in [None, Some(""), Some("   ")] {
        let runtime = IssuerRuntime::new_from_raw(&config, Some(&raw(value, 4)));
        assert!(matches!(
            runtime.state().as_ref(),
            IssuerRuntimeState::Pending {
                persisted_generation: 4
            }
        ));
        assert!(!runtime.is_awaiting_configuration());
        assert_eq!(runtime.state().phase(), SystemPhase::IssuerInvalid);
    }

    let invalid = IssuerRuntime::new_from_raw(&config, Some(&raw(Some("not-a-url"), 5)));
    assert!(matches!(
        invalid.state().as_ref(),
        IssuerRuntimeState::Invalid {
            persisted_generation: 5,
            loaded_generation: None
        }
    ));

    let ready =
        IssuerRuntime::new_from_raw(&config, Some(&raw(Some("https://auth.example.com"), 6)));
    assert!(matches!(
        ready.state().as_ref(),
        IssuerRuntimeState::Ready(snapshot) if snapshot.generation() == 6
    ));
}

#[test]
fn apply_raw_preserves_pending_as_a_fail_closed_persisted_state() {
    let config = config();
    let runtime = IssuerRuntime::new_from_raw(&config, None);

    assert!(runtime.apply_raw(Some(&raw(None, 2))).is_ok());
    assert!(matches!(
        runtime.state().as_ref(),
        IssuerRuntimeState::Pending {
            persisted_generation: 2
        }
    ));
    assert!(!runtime.is_awaiting_configuration());

    let applied = runtime
        .apply_raw(Some(&raw(Some("https://auth.example.com"), 3)))
        .expect("valid issuer");
    assert!(applied.is_some());
    assert!(matches!(
        runtime.state().as_ref(),
        IssuerRuntimeState::Ready(snapshot) if snapshot.generation() == 3
    ));

    assert!(runtime.apply_raw(Some(&raw(Some("invalid"), 4))).is_err());
    assert!(matches!(
        runtime.state().as_ref(),
        IssuerRuntimeState::Invalid {
            persisted_generation: 4,
            loaded_generation: Some(3)
        }
    ));
}

#[test]
fn stale_none_apply_raw_does_not_clear_ready_pending_or_invalid() {
    let config = config();
    let ready =
        IssuerRuntime::new_from_raw(&config, Some(&raw(Some("https://auth.example.com"), 6)));
    assert!(ready.apply_raw(None).expect("absence is ignored").is_none());
    assert!(matches!(
        ready.state().as_ref(),
        IssuerRuntimeState::Ready(snapshot) if snapshot.generation() == 6
    ));

    let pending = IssuerRuntime::new_from_raw(&config, Some(&raw(None, 4)));
    assert!(
        pending
            .apply_raw(None)
            .expect("absence is ignored")
            .is_none()
    );
    assert!(matches!(
        pending.state().as_ref(),
        IssuerRuntimeState::Pending {
            persisted_generation: 4
        }
    ));

    let invalid = IssuerRuntime::new_from_raw(&config, Some(&raw(Some("not-a-url"), 5)));
    assert!(
        invalid
            .apply_raw(None)
            .expect("absence is ignored")
            .is_none()
    );
    assert!(matches!(
        invalid.state().as_ref(),
        IssuerRuntimeState::Invalid {
            persisted_generation: 5,
            loaded_generation: None
        }
    ));
}

#[test]
fn apply_raw_ignores_an_older_generation() {
    let config = config();
    let runtime =
        IssuerRuntime::new_from_raw(&config, Some(&raw(Some("https://new.example.com"), 11)));
    assert!(
        runtime
            .apply_raw(Some(&raw(Some("https://old.example.com"), 10)))
            .expect("older generation is ignored")
            .is_none()
    );
    assert_ready_generation(&runtime, 11, "https://new.example.com");
}

#[test]
fn stale_absence_does_not_replace_a_concurrent_ready_state() {
    let config = config();
    let runtime = IssuerRuntime::new_from_raw(&config, None);
    let query_snapshot = runtime.state();

    runtime
        .apply(&record("https://auth.example.com", 2))
        .expect("concurrent issuer apply");
    runtime
        .apply_raw_if_unchanged(&query_snapshot, None)
        .expect("stale absence is ignored");

    assert!(matches!(
        runtime.state().as_ref(),
        IssuerRuntimeState::Ready(snapshot)
            if snapshot.generation() == 2
                && snapshot.issuer().as_str() == "https://auth.example.com"
    ));
}

#[test]
fn stale_record_does_not_replace_a_concurrent_new_state() {
    let config = config();
    let runtime = IssuerRuntime::new_from_raw(&config, None);
    let query_snapshot = runtime.state();

    runtime
        .apply(&record("https://new.example.com", 3))
        .expect("concurrent issuer apply");
    runtime
        .apply_raw_if_unchanged(
            &query_snapshot,
            Some(&raw(Some("https://stale.example.com"), 4)),
        )
        .expect("stale record is ignored");

    assert!(matches!(
        runtime.state().as_ref(),
        IssuerRuntimeState::Ready(snapshot)
            if snapshot.generation() == 3
                && snapshot.issuer().as_str() == "https://new.example.com"
    ));
}

fn stale_race_cases() -> [(Option<Option<&'static str>>, &'static str); 5] {
    [
        (None, "https://new.example.com"),
        (
            Some(Some("https://old.example.com")),
            "https://new.example.com",
        ),
        (Some(None), "https://new.example.com"),
        (Some(Some("")), "https://new.example.com"),
        (Some(Some("not-a-url")), "https://new.example.com"),
    ]
}

fn assert_ready_generation(runtime: &IssuerRuntime, generation: i64, issuer: &str) {
    assert!(
        matches!(
            runtime.state().as_ref(),
            IssuerRuntimeState::Ready(snapshot)
                if snapshot.generation() == generation
                    && snapshot.issuer().as_str() == issuer
        ),
        "runtime generation {:?}, issuer {:?}",
        runtime.state().persisted_generation(),
        runtime
            .current()
            .map(|snapshot| snapshot.issuer().as_str().to_owned())
    );
}

#[test]
fn barrier_old_reads_cannot_publish_over_a_new_generation_for_all_raw_states() {
    let config = config();
    for use_cas in [true, false] {
        for (old_value, new_value) in stale_race_cases() {
            let initial_raw = old_value.map(|value| raw(value, 10));
            let runtime = IssuerRuntime::new_from_raw(&config, initial_raw.as_ref());
            let expected = runtime.state();
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let worker = runtime.clone();
            let worker_entered = entered.clone();
            let worker_release = release.clone();
            let old_record = old_value.map(|value| raw(value, 10));
            let handle = thread::spawn(move || {
                worker_entered.wait();
                worker_release.wait();
                if use_cas {
                    worker
                        .apply_raw_if_unchanged(&expected, old_record.as_ref())
                        .expect("stale worker transition");
                } else {
                    worker
                        .apply_raw(old_record.as_ref())
                        .expect("stale worker transition");
                }
            });

            entered.wait();
            runtime
                .apply(&record(new_value, 11))
                .expect("new generation apply");
            release.wait();
            handle.join().expect("worker join");
            assert_ready_generation(&runtime, 11, "https://new.example.com");
        }
    }
}

#[test]
fn concurrent_runtime_clones_never_publish_a_lower_generation() {
    let config = config();
    let runtime = IssuerRuntime::new_from_raw(&config, None);
    let start = Arc::new(Barrier::new(11));
    let mut handles = Vec::new();
    for generation in (1..=8).rev() {
        let runtime = runtime.clone();
        let start = start.clone();
        let config_value = format!("https://issuer-{generation}.example.com");
        handles.push(thread::spawn(move || {
            start.wait();
            runtime
                .apply(&record(&config_value, generation))
                .expect("valid concurrent issuer");
        }));
    }
    for _ in 0..2 {
        let runtime = runtime.clone();
        let start = start.clone();
        handles.push(thread::spawn(move || {
            start.wait();
            runtime.apply_raw(None).expect("stale absence is ignored");
        }));
    }
    start.wait();
    for handle in handles {
        handle.join().expect("issuer clone join");
    }
    assert_ready_generation(&runtime, 8, "https://issuer-8.example.com");
}

#[test]
fn local_login_decision_is_shared_and_fail_closed() {
    let config = config();
    let awaiting = IssuerRuntime::new_from_raw(&config, None);
    assert!(awaiting.local_login_allowed(INITIAL_OWNER_ID));
    assert!(!awaiting.local_login_allowed(INITIAL_OWNER_ID + 1));

    let ready =
        IssuerRuntime::new_from_raw(&config, Some(&raw(Some("https://auth.example.com"), 1)));
    assert!(ready.local_login_allowed(INITIAL_OWNER_ID + 1));

    let pending = IssuerRuntime::new_from_raw(&config, Some(&raw(None, 1)));
    for runtime in [pending, IssuerRuntime::new_invalid(&config, 1)] {
        assert!(!runtime.local_login_allowed(INITIAL_OWNER_ID));
        assert!(!runtime.local_login_allowed(INITIAL_OWNER_ID + 1));
    }
}
