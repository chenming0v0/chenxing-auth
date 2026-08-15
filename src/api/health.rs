//! 健康检查端点：存活探针与就绪探针。

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::time::Duration;

use crate::{redis_client::RedisClient, state::AppState};

/// 探针结果随依赖即时变化，禁止被中间缓存存成成功或失败。
const HEALTH_CACHE_CONTROL: &str = "no-store";

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

fn health_response(status: StatusCode, status_text: &'static str) -> Response {
    (
        status,
        [(CACHE_CONTROL, HEALTH_CACHE_CONTROL)],
        Json(HealthResponse {
            status: status_text,
            service: crate::SERVICE_NAME,
        }),
    )
        .into_response()
}

/// 存活探针：只报告进程本身，不触碰任何外部依赖。
pub(super) async fn health_live() -> Response {
    health_response(StatusCode::OK, "ok")
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
        return health_response(StatusCode::OK, "ok");
    }

    tracing::warn!(
        event = "readiness_check_failed",
        database = database_ready,
        redis = redis_ready,
        issuer = issuer_ready,
        "application dependencies are not ready"
    );
    health_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

/// 匿名引导状态。只回答 Owner 是否已初始化，不暴露 Issuer 收敛内部状态。
///
/// generation / phase / persisted 属于 `GET /api/v1/admin/settings/issuer`，需要
/// ManageIssuer。匿名端点若按收敛异常分流，Owner 已存在时不同 503 会重新打开预言机。
pub(super) async fn system_status(State(state): State<AppState>) -> Response {
    crate::admin::auth_handlers::bootstrap_status(State(state)).await
}

async fn issuer_converged(state: &AppState) -> bool {
    let persisted = match crate::settings::issuer::load_raw(&state.database).await {
        Ok(persisted) => persisted,
        Err(_) => return false,
    };
    let runtime = state.issuer.state();
    match (persisted, runtime.as_ref()) {
        (None, crate::settings::IssuerRuntimeState::AwaitingIssuer) => true,
        (Some(persisted), crate::settings::IssuerRuntimeState::Ready(loaded)) => {
            let Some(value) = persisted.value else {
                return false;
            };
            let Ok(value) = crate::config::IssuerUrl::parse(&value) else {
                return false;
            };
            persisted.generation == loaded.generation()
                && value.as_str() == loaded.issuer().as_str()
        }
        _ => false,
    }
}

async fn redis_ready(client: &RedisClient) -> Result<(), redis::RedisError> {
    let mut connection = client.get_multiplexed_async_connection().await?;
    let _: String = redis::cmd("PING").query_async(&mut connection).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok_and_unavailable_are_not_stored() {
        for (status, text) in [
            (StatusCode::OK, "ok"),
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        ] {
            let response = health_response(status, text);
            assert_eq!(response.status(), status, "{text}");
            assert_eq!(
                response
                    .headers()
                    .get(CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some(HEALTH_CACHE_CONTROL),
                "{text}"
            );
        }
    }
}
