//! Process-level HTTP + worker shutdown with a bounded HTTP drain.
//!
//! Axum graceful shutdown only stops accepting and then waits for connection
//! tasks. Handler timeouts do not cover static SPA/asset responses or a client
//! that never reads the body, so an unbounded `server.await` can stall rolling
//! restarts. This module notifies HTTP and workers together, waits for both
//! drains in parallel, and aborts leftover HTTP work when the HTTP deadline
//! elapses.

use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    time::Duration,
};

use axum::Router;
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

use crate::workers::{WORKER_DRAIN_TIMEOUT, WorkerDrainError, WorkerFailure, WorkerSupervisor};

/// Outcome of waiting for the first process-exit trigger.
enum ServiceExit {
    Server(io::Result<()>),
    ShutdownSignal,
    Worker(WorkerFailure),
}

#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    #[error(transparent)]
    Server(#[from] io::Error),
    #[error(transparent)]
    Worker(#[from] WorkerFailure),
    #[error(transparent)]
    Drain(#[from] WorkerDrainError),
}

/// Serve HTTP until a shutdown signal, listener failure, or critical worker exit.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    workers: WorkerSupervisor,
    http_drain_timeout: Duration,
) -> Result<(), ShutdownError> {
    serve_until(
        listener,
        app,
        workers,
        http_drain_timeout,
        shutdown_signal(),
    )
    .await
}

/// Same orchestration as [`serve`], with an injected shutdown trigger for tests.
pub async fn serve_until(
    listener: TcpListener,
    app: Router,
    mut workers: WorkerSupervisor,
    http_drain_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ShutdownError> {
    let (http_shutdown, http_shutdown_receiver) = watch::channel(false);
    let mut server = tokio::spawn(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(http_shutdown_receiver))
        .into_future(),
    );

    let exit = tokio::select! {
        result = &mut server => ServiceExit::Server(flatten_server(result)),
        _ = shutdown => ServiceExit::ShutdownSignal,
        failure = workers.wait_for_failure() => ServiceExit::Worker(failure),
    };

    finish(
        exit,
        server,
        http_shutdown,
        &mut workers,
        http_drain_timeout,
    )
    .await
}

async fn finish(
    exit: ServiceExit,
    server: JoinHandle<io::Result<()>>,
    http_shutdown: watch::Sender<bool>,
    workers: &mut WorkerSupervisor,
    http_drain_timeout: Duration,
) -> Result<(), ShutdownError> {
    match exit {
        ServiceExit::Server(result) => {
            let drain_result = workers.drain(WORKER_DRAIN_TIMEOUT).await;
            result?;
            Ok(drain_result?)
        }
        ServiceExit::ShutdownSignal => {
            tracing::info!("shutdown signal received; draining HTTP and workers");
            complete_signaled_exit(server, http_shutdown, workers, http_drain_timeout, None).await
        }
        ServiceExit::Worker(failure) => {
            tracing::error!(error = %failure, "critical worker failed; draining HTTP and workers");
            complete_signaled_exit(
                server,
                http_shutdown,
                workers,
                http_drain_timeout,
                Some(failure),
            )
            .await
        }
    }
}

/// Notify HTTP and workers in the same turn, then drain both under their own bounds.
async fn complete_signaled_exit(
    server: JoinHandle<io::Result<()>>,
    http_shutdown: watch::Sender<bool>,
    workers: &mut WorkerSupervisor,
    http_drain_timeout: Duration,
    worker_failure: Option<WorkerFailure>,
) -> Result<(), ShutdownError> {
    let _ = http_shutdown.send(true);
    workers.begin_shutdown();

    let (server_result, drain_result) = tokio::join!(
        drain_http(server, http_drain_timeout),
        workers.drain(WORKER_DRAIN_TIMEOUT),
    );

    if let Some(failure) = worker_failure {
        if let Err(error) = &server_result {
            tracing::error!(error = %error, "HTTP server also failed after worker exit");
        }
        if let Err(error) = &drain_result {
            tracing::error!(error = %error, "worker drain also failed after worker exit");
        }
        return Err(failure.into());
    }

    server_result?;
    Ok(drain_result?)
}

/// Wait for graceful HTTP drain, then abort the server task at the deadline.
///
/// Dropping the `JoinHandle` is not enough: the spawned Serve future keeps
/// connection tasks alive until the task itself is aborted.
async fn drain_http(mut server: JoinHandle<io::Result<()>>, timeout: Duration) -> io::Result<()> {
    match tokio::time::timeout(timeout, &mut server).await {
        Ok(result) => flatten_server(result),
        Err(_) => {
            tracing::warn!(
                timeout_ms = timeout.as_millis() as u64,
                "HTTP graceful drain timed out; aborting remaining connections"
            );
            server.abort();
            flatten_server(server.await)
        }
    }
}

fn flatten_server(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Ok(()),
    }
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install terminate signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::drain_http;
    use std::{future::pending, time::Duration};

    #[tokio::test]
    async fn http_drain_aborts_a_stuck_server_task_at_the_deadline() {
        let server = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });
        let started = tokio::time::Instant::now();
        drain_http(server, Duration::from_millis(20))
            .await
            .expect("forced HTTP abort is not a server failure");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "aborting leftover HTTP work must not wait on the stuck task"
        );
    }
}
