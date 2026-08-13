use chenxing_auth::{
    api,
    audit::AuditService,
    config::Config,
    db,
    keys::DEFAULT_KEY_SYNC_INTERVAL,
    oauth::quota::QUOTA_REFUND_WORKER_INTERVAL,
    settings::{InitializeIssuerOutcome, issuer},
    state::AppState,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(config.log_filter.clone())
        .with_target(false)
        .init();

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
                    info!("issuer configured; restart the application to enable all routes")
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
    let issuer_configured = state.config.issuer_configured;
    let workers = issuer_configured.then(|| {
        // 协议路由关闭时不运行任何认证后台任务；配置 Issuer 并重启后再统一启用。
        let session_outbox = tokio::spawn(state.sessions.clone().run_outbox_worker());
        // 密钥热路径只读内存快照，与共享 KEY_DIRECTORY 的一致性由这个后台任务负责：
        // 磁盘 IO 隔离在阻塞线程池，抢不到目录锁时跳过本轮而不影响任何请求（Issue #257）。
        let key_sync = tokio::spawn(
            state
                .keys
                .clone()
                .run_disk_sync_worker(DEFAULT_KEY_SYNC_INTERVAL),
        );
        // 过期未兑换的授权码要退还签发时消耗的套餐配额（Issue #341）。消费与兑换
        // 都发生在请求路径上，唯独「过期」没有请求会经过，只能由后台任务兜底。
        let quota_refund = tokio::spawn(
            state
                .oauth_quotas
                .clone()
                .run_refund_worker(state.clock.clone(), QUOTA_REFUND_WORKER_INTERVAL),
        );
        [session_outbox, key_sync, quota_refund]
    });
    let app = api::router(state);
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&address).await?;

    info!(address = %address, issuer_configured, "辰星认证中枢 started");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    for worker in workers.into_iter().flatten() {
        worker.abort();
    }

    Ok(())
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
