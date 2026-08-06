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
    if database_ready && redis_ready {
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

async fn redis_ready(client: &RedisClient) -> Result<(), redis::RedisError> {
    let mut connection = client.get_multiplexed_async_connection().await?;
    let _: String = redis::cmd("PING").query_async(&mut connection).await?;
    Ok(())
}
