use chenxing_auth::{api, audit::AuditService, config::Config, db, state::AppState};
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
            let database = db::connect(&config)?;
            db::migrate(&database).await?;
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
            let database = db::connect(&config)?;
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
