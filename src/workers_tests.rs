use std::{
    future::pending,
    time::{Duration, Instant},
};

use super::*;

#[test]
fn readiness_requires_fresh_success_from_every_critical_worker() {
    let health = WorkerHealth::new();
    assert!(!health.is_ready());

    let mut guards = Vec::new();
    for worker in WorkerName::ALL {
        guards.push(health.start(worker));
        health.reporter(worker).success();
    }

    let readiness = health.readiness();
    assert!(readiness.ready);
    assert!(readiness.workers.iter().all(|worker| {
        worker.phase == WorkerPhase::Running
            && worker.last_heartbeat_age.is_some()
            && worker.last_success_age.is_some()
            && worker.consecutive_failures == 0
    }));

    drop(guards);
}

#[test]
fn repeated_pass_failures_make_the_worker_unready() {
    let health = WorkerHealth::new();
    let mut guards = Vec::new();
    for worker in WorkerName::ALL {
        guards.push(health.start(worker));
        health.reporter(worker).success();
    }

    let reporter = health.reporter(WorkerName::SessionOutbox);
    for _ in 0..WorkerName::SessionOutbox.policy().max_consecutive_failures {
        reporter.retryable_failure();
    }

    let readiness = health.readiness();
    assert!(!readiness.ready);
    let outbox = readiness
        .workers
        .iter()
        .find(|worker| worker.name == WorkerName::SessionOutbox)
        .expect("session outbox health");
    assert_eq!(
        outbox.consecutive_failures,
        WorkerName::SessionOutbox.policy().max_consecutive_failures
    );

    drop(guards);
}

#[test]
fn stale_heartbeat_and_last_success_make_the_worker_unready() {
    let health = WorkerHealth::new();
    let _guard = health.start(WorkerName::KeySync);
    health.reporter(WorkerName::KeySync).success();

    let stale_at =
        Instant::now() + WorkerName::KeySync.policy().success_timeout + Duration::from_secs(1);
    let status = health.status_at(WorkerName::KeySync, stale_at);
    assert!(!status.ready);
    assert!(
        status.last_success_age.expect("last success")
            > WorkerName::KeySync.policy().success_timeout
    );
}

#[test]
fn explicit_unready_report_is_immediate_and_recoverable() {
    let health = WorkerHealth::new();
    let mut guards = Vec::new();
    for worker in WorkerName::ALL {
        guards.push(health.start(worker));
        health.reporter(worker).success();
    }

    let reporter = health.reporter(WorkerName::KeySync);
    reporter.report_unready();
    assert!(!health.is_ready());
    reporter.success();
    assert!(health.is_ready());

    drop(guards);
}

#[tokio::test]
async fn unexpected_return_is_reported_and_marks_the_worker_failed() {
    let health = WorkerHealth::new();
    let mut supervisor = WorkerSupervisor::new(health.clone());
    supervisor.spawn(WorkerName::IssuerSync, |_context| async {});

    let failure = supervisor.wait_for_failure().await;
    assert!(matches!(
        failure,
        WorkerFailure::Returned(WorkerName::IssuerSync)
    ));
    assert_eq!(
        health.status(WorkerName::IssuerSync).phase,
        WorkerPhase::Failed
    );
    assert!(!health.is_ready());
}

#[tokio::test]
async fn panic_is_reported_and_marks_the_worker_failed() {
    let health = WorkerHealth::new();
    let mut supervisor = WorkerSupervisor::new(health.clone());
    supervisor.spawn(WorkerName::KeySync, |_context| async {
        panic!("simulated key sync panic");
    });

    let failure = supervisor.wait_for_failure().await;
    assert!(matches!(
        failure,
        WorkerFailure::Task {
            worker: WorkerName::KeySync,
            ..
        }
    ));
    assert_eq!(
        health.status(WorkerName::KeySync).phase,
        WorkerPhase::Failed
    );
    assert!(!health.is_ready());
}

#[tokio::test]
async fn shutdown_waits_for_a_cooperative_worker() {
    let health = WorkerHealth::new();
    let mut supervisor = WorkerSupervisor::new(health.clone());
    supervisor.spawn(WorkerName::QuotaRefund, |mut context| async move {
        context.reporter().success();
        context.wait_for_shutdown().await;
    });

    supervisor
        .drain(Duration::from_secs(1))
        .await
        .expect("cooperative worker drain");
    assert_eq!(
        health.status(WorkerName::QuotaRefund).phase,
        WorkerPhase::Stopped
    );
}

#[tokio::test]
async fn shutdown_aborts_only_after_the_drain_deadline() {
    let health = WorkerHealth::new();
    let mut supervisor = WorkerSupervisor::new(health);
    supervisor.spawn(WorkerName::SessionOutbox, |_context| async {
        pending::<()>().await;
    });

    let error = supervisor
        .drain(Duration::from_millis(1))
        .await
        .expect_err("non-cooperative worker must hit the bounded deadline");
    assert!(matches!(error, WorkerDrainError::TimedOut { aborted: 1 }));
}
