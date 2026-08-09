use chenxing_auth::{
    api, audit::AuditService, config::Config, db, keys::DEFAULT_KEY_SYNC_INTERVAL, state::AppState,
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

    match std::env::args().nth(1).as_deref() {
        Some("migrate") => {
            let migration_database_url = std::env::var("MIGRATION_DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| config.database_url.clone());
            if std::env::var("MIGRATION_DATABASE_URL").is_ok_and(|value| !value.trim().is_empty()) {
                let migration_role = url::Url::parse(&migration_database_url)
                    .ok()
                    .map(|value| value.username().to_owned())
                    .unwrap_or_default();
                let runtime_role = url::Url::parse(&config.database_url)
                    .ok()
                    .map(|value| value.username().to_owned())
                    .unwrap_or_default();
                if migration_role == runtime_role {
                    return Err(
                        "MIGRATION_DATABASE_URL must use a role different from the runtime \
                         DATABASE_URL so the runtime role cannot mutate audit tables"
                            .into(),
                    );
                }
                if runtime_role != chenxing_auth::db::RUNTIME_DATABASE_ROLE {
                    return Err(
                        "runtime DATABASE_URL must use the chenxing_runtime role when \
                         MIGRATION_DATABASE_URL is set"
                            .into(),
                    );
                }
            }
            // 迁移走维护池：不带 statement_timeout，长时间的 DDL 不会被中途取消。
            let database = db::connect_maintenance(&migration_database_url)?;
            db::migrate(&database).await?;
            db::configure_runtime_role(&database, &config.database_url).await?;
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
        _ => {}
    }

    let state = AppState::new(config.clone()).await?;
    let session_outbox_worker = tokio::spawn(state.sessions.clone().run_outbox_worker());
    // 密钥热路径只读内存快照，与共享 KEY_DIRECTORY 的一致性由这个后台任务负责：
    // 磁盘 IO 隔离在阻塞线程池，抢不到目录锁时跳过本轮而不影响任何请求（Issue #257）。
    let key_sync_worker = tokio::spawn(
        state
            .keys
            .clone()
            .run_disk_sync_worker(DEFAULT_KEY_SYNC_INTERVAL),
    );
    let app = api::router(state);
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&address).await?;

    info!(address = %address, "辰星认证中枢 started");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    session_outbox_worker.abort();
    key_sync_worker.abort();

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
