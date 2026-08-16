use chenxing_auth::{
    api,
    audit::AuditService,
    config::Config,
    db,
    keys::DEFAULT_KEY_SYNC_INTERVAL,
    oauth::quota::QUOTA_REFUND_WORKER_INTERVAL,
    settings::{InitializeIssuerOutcome, issuer},
    state::AppState,
    workers::{WORKER_DRAIN_TIMEOUT, WorkerFailure, WorkerName, WorkerSupervisor},
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(config.log_filter.clone())
        .with_target(false)
        .init();
    if config.redis_keyspace.is_legacy() {
        warn!(
            redis_namespace = %config.redis_keyspace,
            "Redis legacy key mode is active; configure a unique REDIS_NAMESPACE for new deployments"
        );
    } else {
        info!(
            redis_namespace = %config.redis_keyspace,
            "Redis key namespace configured"
        );
    }

    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("migrate") => {
            // 角色姿态先解析再连库：单角色部署（未配置 MIGRATION_DATABASE_URL）在
            // 这里就被拒绝，不会先跑完迁移再报错（Issue #281）。
            let plan = db::MigrationPlan::from_env(&config.database_url)?;
            plan.log_posture();
            // 迁移走维护池：不带 statement_timeout，长时间的 DDL 不会被中途取消。
            let database = db::connect_maintenance(plan.migration_database_url())?;
            db::migrate(&database).await?;
            db::configure_runtime_role(
                &database,
                plan.runtime_database_url(),
                plan.password_policy(),
            )
            .await?;
            // 迁移文件里写了 REVOKE 不等于边界成立：owner 隐含全部表权限。
            // 这一步直接问数据库运行时角色此刻能不能改审计表。
            db::verify_audit_append_only_boundary(
                &database,
                plan.runtime_role(),
                plan.separation(),
            )
            .await?;
            info!("database migrations completed");
            return Ok(());
        }
        Some("audit-archive") => {
            if !config.audit_retention.enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "AUDIT_ARCHIVE_ENABLED must be true before scheduling audit-archive",
                )
                .into());
            }
            // 归档批次扫描审计热表，耗时随保留窗口和数据量变化，同样走维护池。
            let database = db::connect_maintenance(&config.database_url)?;
            let archived = AuditService::new(database)
                .archive_expired(config.audit_retention.retention_days)
                .await?;
            info!(
                archived,
                retention_days = config.audit_retention.retention_days,
                "audit archive batch completed"
            );
            return Ok(());
        }
        Some("configure-issuer") => {
            let value = arguments.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "usage: chenxing-auth configure-issuer https://auth.example.com",
                )
            })?;
            if arguments.next().is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configure-issuer accepts exactly one URL",
                )
                .into());
            }
            let database = db::connect(&config)?;
            match issuer::initialize(&database, &value).await? {
                InitializeIssuerOutcome::Created => {
                    info!(
                        "issuer configured; running instances will hot-load it through the issuer sync worker"
                    )
                }
                InitializeIssuerOutcome::AlreadyConfigured => {
                    info!("issuer already has the requested value")
                }
                InitializeIssuerOutcome::Conflict => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "issuer is already configured with a different value; explicit data migration is required",
                    )
                    .into());
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let state = AppState::new_with_persisted_issuer(config.clone()).await?;
    // Migrations verify this boundary once, but grants can change before service startup.
    // Recheck before workers or the listener start so the web process fails closed (#427).
    let audit_posture = db::RuntimeAuditPosture::from_env(&config.database_url)?;
    db::verify_audit_append_only_boundary(
        &state.database,
        audit_posture.runtime_role(),
        audit_posture.separation(),
    )
    .await?;
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&address).await?;
    let mut workers = WorkerSupervisor::new(state.worker_health.clone());

    // Route admission is runtime-gated, so worker startup cannot be frozen by the issuer
    // state observed during construction. All four tasks are supervised: a panic or return
    // removes readiness immediately and initiates process shutdown.
    let issuer_state = state.clone();
    workers.spawn(WorkerName::IssuerSync, move |worker| {
        issuer_state.run_issuer_sync_worker(worker)
    });
    let sessions = state.sessions.clone();
    workers.spawn(WorkerName::SessionOutbox, move |worker| {
        sessions.run_outbox_worker(worker)
    });
    let keys = state.keys.clone();
    workers.spawn(WorkerName::KeySync, move |worker| {
        keys.run_disk_sync_worker(DEFAULT_KEY_SYNC_INTERVAL, worker)
    });
    let quotas = state.oauth_quotas.clone();
    let quota_clock = state.clock.clone();
    workers.spawn(WorkerName::QuotaRefund, move |worker| {
        quotas.run_refund_worker(quota_clock, QUOTA_REFUND_WORKER_INTERVAL, worker)
    });

    let app = api::router(state);
    let (http_shutdown, http_shutdown_receiver) = tokio::sync::watch::channel(false);
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(http_shutdown_receiver))
    .into_future();
    tokio::pin!(server);

    info!(address = %address, "辰星认证中枢 started");

    enum ServiceExit {
        Server(std::io::Result<()>),
        ShutdownSignal,
        Worker(WorkerFailure),
    }

    let exit = tokio::select! {
        result = &mut server => ServiceExit::Server(result),
        _ = shutdown_signal() => ServiceExit::ShutdownSignal,
        failure = workers.wait_for_failure() => ServiceExit::Worker(failure),
    };
    let (server_result, worker_failure) = match exit {
        ServiceExit::Server(result) => (result, None),
        ServiceExit::ShutdownSignal => {
            let _ = http_shutdown.send(true);
            (server.await, None)
        }
        ServiceExit::Worker(failure) => {
            tracing::error!(error = %failure, "critical worker failed; shutting down service");
            let _ = http_shutdown.send(true);
            (server.await, Some(failure))
        }
    };

    let drain_result = workers.drain(WORKER_DRAIN_TIMEOUT).await;
    server_result?;
    if let Some(failure) = worker_failure {
        if let Err(drain_error) = &drain_result {
            tracing::error!(error = %drain_error, "worker drain also failed after worker exit");
        }
        return Err(failure.into());
    }
    drain_result?;

    Ok(())
}

async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
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
