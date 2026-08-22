use chenxing_auth::{
    api,
    audit::AuditService,
    config::{self, Config},
    db,
    keys::DEFAULT_KEY_SYNC_INTERVAL,
    oauth::quota::QUOTA_REFUND_WORKER_INTERVAL,
    settings::{InitializeIssuerOutcome, issuer},
    shutdown,
    state::AppState,
    workers::{WorkerName, WorkerSupervisor},
};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    // Construction returns posture diagnostics as data. Emit only after a
    // subscriber exists; `tracing::warn!` inside `from_env` is dropped.
    config::install_tracing(&config.log_filter)?;
    config.emit_startup_warnings();
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
            // 校验读的是这条连接上的 current_user / session_user，所以必须连
            // DATABASE_URL 声称的运行时角色，而不是刚跑完 DDL 的 owner 连接
            // （Issue #649：代理或 SET ROLE 会让 URL 用户名和有效主体分叉）。
            let runtime_database = db::connect_maintenance(plan.runtime_database_url())?;
            db::verify_audit_append_only_boundary(
                &runtime_database,
                plan.runtime_role(),
                plan.separation(),
            )
            .await?;
            runtime_database.close().await;
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

    // The web process never mutates schema, but it must not serve a newer binary against an
    // older database. Verify the ledger before application-state construction performs queries
    // that depend on the latest columns and functions.
    let startup_database = db::connect(&config)?;
    db::verify_schema_current(&startup_database).await?;
    startup_database.close().await;
    let state = AppState::new_with_persisted_issuer(config.clone()).await?;
    // Migrations verify this boundary once, but grants can change before service startup.
    // Recheck the application pool before workers start so the web process fails closed
    // (#427). The URL username is only the claimed role; the verifier reads
    // current_user / session_user on a live connection (#649).
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
    // state observed during construction. All five tasks are supervised: a panic or return
    // removes readiness immediately and initiates process shutdown.
    let issuer_state = state.clone();
    workers.spawn(WorkerName::IssuerSync, move |worker| {
        issuer_state.run_issuer_sync_worker(worker)
    });
    let sessions = state.sessions.clone();
    workers.spawn(WorkerName::SessionOutbox, move |worker| {
        sessions.run_outbox_worker(worker)
    });
    let email_outbox = state.email_outbox.clone();
    workers.spawn(WorkerName::EmailOutbox, move |worker| {
        email_outbox.run_worker(worker)
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
    info!(address = %address, "辰星认证中枢 started");
    shutdown::serve(
        listener,
        app,
        workers,
        Duration::from_secs(config.http_graceful_drain_seconds),
    )
    .await?;
    Ok(())
}
