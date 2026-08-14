//! 健康检查端点：存活探针与就绪探针。

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::time::Duration;

use crate::{redis_client::RedisClient, state::AppState};

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// 存活探针：只报告进程本身，不触碰任何外部依赖。
pub(super) async fn health_live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: crate::SERVICE_NAME,
    })
}

pub(super) async fn health(State(state): State<AppState>) -> Response {
    health_ready(State(state)).await
}

/// 就绪探针：检查数据库和 Redis。
///
/// 响应体只暴露聚合状态，不包含连接串、主机名或错误细节，避免泄露内部拓扑。
pub(super) async fn health_ready(State(state): State<AppState>) -> Response {
    let (database_result, redis_result) = tokio::join!(
        tokio::time::timeout(
            HEALTH_CHECK_TIMEOUT,
            crate::db::check_ready(&state.database)
        ),
        tokio::time::timeout(HEALTH_CHECK_TIMEOUT, redis_ready(&state.redis)),
    );
    let database_ready = matches!(database_result, Ok(Ok(())));
    let redis_ready = matches!(redis_result, Ok(Ok(())));
    let issuer_ready = if database_ready {
        issuer_converged(&state).await
    } else {
        false
    };
    if database_ready && redis_ready && issuer_ready {
        return (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                service: crate::SERVICE_NAME,
            }),
        )
            .into_response();
    }

    tracing::warn!(
        event = "readiness_check_failed",
        database = database_ready,
        redis = redis_ready,
        issuer = issuer_ready,
        "application dependencies are not ready"
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(HealthResponse {
            status: "unavailable",
            service: crate::SERVICE_NAME,
        }),
    )
        .into_response()
}

pub(super) async fn system_status(State(state): State<AppState>) -> Response {
    let persisted = match crate::settings::issuer::load(&state.database).await {
        Ok(persisted) => persisted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load issuer bootstrap status");
            return crate::error::service_unavailable(
                "issuer_status_unavailable",
                "the application issuer status is unavailable",
            );
        }
    };
    let runtime = state.issuer.state();
    if persisted.is_none() && runtime.loaded().is_some() {
        return crate::admin::auth_handlers::bootstrap_status(State(state)).await;
    }
    if persisted.is_none()
        && matches!(
            runtime.as_ref(),
            crate::settings::IssuerRuntimeState::AwaitingIssuer
        )
    {
        return crate::admin::auth_handlers::bootstrap_status(State(state)).await;
    }
    if let (Some(persisted), Some(loaded)) = (persisted.as_ref(), runtime.loaded())
        && persisted.generation == loaded.generation()
        && persisted.value == loaded.issuer().as_str()
    {
        return crate::admin::auth_handlers::bootstrap_status(State(state)).await;
    }

    let (code, message) = match (persisted.as_ref(), runtime.as_ref()) {
        (None, crate::settings::IssuerRuntimeState::AwaitingIssuer) => (
            "issuer_not_configured",
            "configure the persistent application issuer",
        ),
        (_, crate::settings::IssuerRuntimeState::Invalid { .. }) => (
            "issuer_runtime_invalid",
            "the persisted application issuer is invalid",
        ),
        (Some(_), _) => (
            "issuer_pending_reload",
            "the persisted application issuer is waiting to be loaded",
        ),
        (None, _) => (
            "issuer_state_mismatch",
            "the application issuer state is inconsistent",
        ),
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "code": code,
            "message": message,
            "issuer_persisted": persisted.is_some(),
            "persisted_generation": persisted.as_ref().map(|record| record.generation),
            "issuer_loaded": runtime.loaded().is_some(),
            "loaded_generation": runtime.loaded_generation(),
            "phase": runtime.phase(),
        })),
    )
        .into_response()
}

async fn issuer_converged(state: &AppState) -> bool {
    let persisted = match crate::settings::issuer::load(&state.database).await {
        Ok(persisted) => persisted,
        Err(_) => return false,
    };
    match (persisted, state.issuer.state().loaded()) {
        (None, None) => false,
        (Some(persisted), Some(loaded)) => {
            persisted.generation == loaded.generation()
                && persisted.value == loaded.issuer().as_str()
        }
        _ => false,
    }
}

async fn redis_ready(client: &RedisClient) -> Result<(), redis::RedisError> {
    let mut connection = client.get_multiplexed_async_connection().await?;
    let _: String = redis::cmd("PING").query_async(&mut connection).await?;
    Ok(())
}
