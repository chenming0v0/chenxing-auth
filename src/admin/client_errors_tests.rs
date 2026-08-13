//! `client_errors` 的单元测试（Issue #288）。
//!
//! 这里断言的是「哪些 `ClientServiceError` 变体算业务状态、哪些算内部故障」这条
//! 边界。四个映射函数是纯函数，因此不需要数据库、Redis 或 HTTP 栈；
//! `QuotaExceeded` 在管理端注册路径上目前不可达（管理端 Client 无 owner，
//! 不走配额分支），正是这一点让集成测试无法覆盖它——回归只能由这里守住。

use super::*;
use crate::clients::domain::ClientRegistrationError;
use axum::body::to_bytes;
use axum::http::StatusCode;

type Mapper = fn(&ClientServiceError) -> Response;

const MAPPERS: [Mapper; 4] = [
    create_client_error_response,
    update_client_error_response,
    set_client_status_error_response,
    rotate_secret_error_response,
];

async fn parts(response: Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error response body");
    (
        status,
        serde_json::from_slice(&body).expect("error response JSON"),
    )
}

/// 配额超限是调用方可预期、可恢复的业务状态，四个管理端点都不得回 500。
#[tokio::test]
async fn quota_exceeded_maps_to_conflict_on_every_admin_client_endpoint() {
    for mapper in MAPPERS {
        let (status, body) = parts(mapper(&ClientServiceError::QuotaExceeded)).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "quota_exceeded");
    }
}

/// 配额响应属于对外错误体，不得携带 SQL、堆栈或凭据线索。
#[tokio::test]
async fn quota_exceeded_message_carries_no_internal_details() {
    let (_, body) = parts(create_client_error_response(
        &ClientServiceError::QuotaExceeded,
    ))
    .await;

    let message = body["message"].as_str().expect("message");
    for leak in ["SQL", "select", "oauth_clients", "secret"] {
        assert!(!message.contains(leak), "message leaks {leak}: {message}");
    }
}

#[tokio::test]
async fn create_client_maps_validation_to_bad_request() {
    let (status, body) = parts(create_client_error_response(
        &ClientServiceError::Validation(ClientRegistrationError::InsecureRedirectUri),
    ))
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_client_registration");
}

#[tokio::test]
async fn create_client_keeps_internal_failures_as_internal_error() {
    for error_value in [
        ClientServiceError::SecretHash,
        ClientServiceError::InvalidData,
        ClientServiceError::SecretRotationConflict,
        ClientServiceError::Database(crate::sqlx::Error::PoolClosed),
    ] {
        let (status, body) = parts(create_client_error_response(&error_value)).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "internal_error");
    }
}

#[tokio::test]
async fn update_client_keeps_internal_failures_as_internal_error() {
    for error_value in [
        ClientServiceError::SecretHash,
        ClientServiceError::InvalidData,
        ClientServiceError::SecretRotationConflict,
        ClientServiceError::Database(crate::sqlx::Error::PoolClosed),
    ] {
        let (status, body) = parts(update_client_error_response(&error_value)).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "internal_error");
    }
}

#[tokio::test]
async fn set_client_status_keeps_invalid_status_as_bad_request() {
    let (status, body) = parts(set_client_status_error_response(
        &ClientServiceError::InvalidData,
    ))
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_status");
}

#[tokio::test]
async fn set_client_status_keeps_internal_failures_as_internal_error() {
    for error_value in [
        ClientServiceError::SecretHash,
        ClientServiceError::SecretRotationConflict,
        ClientServiceError::Validation(ClientRegistrationError::MissingScope),
        ClientServiceError::Database(crate::sqlx::Error::PoolClosed),
    ] {
        let (status, body) = parts(set_client_status_error_response(&error_value)).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "internal_error");
    }
}

#[tokio::test]
async fn rotate_secret_keeps_missing_client_as_not_found() {
    let (status, body) = parts(rotate_secret_error_response(
        &ClientServiceError::InvalidData,
    ))
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "client_not_found");
}

/// handler 会先行匹配该变体去写一条冲突审计，但两条路径的对外响应必须一致。
#[tokio::test]
async fn rotate_secret_keeps_rotation_conflict_as_conflict() {
    let (status, body) = parts(rotate_secret_error_response(
        &ClientServiceError::SecretRotationConflict,
    ))
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "client_secret_rotation_conflict");
}

#[tokio::test]
async fn rotate_secret_keeps_internal_failures_as_internal_error() {
    for error_value in [
        ClientServiceError::SecretHash,
        ClientServiceError::Validation(ClientRegistrationError::InvalidScope),
        ClientServiceError::Database(crate::sqlx::Error::PoolClosed),
    ] {
        let (status, body) = parts(rotate_secret_error_response(&error_value)).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "internal_error");
    }
}
