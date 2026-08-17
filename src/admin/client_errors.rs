//! 管理端 Client 端点的 [`ClientServiceError`] → HTTP 响应映射。
//!
//! 四个端点对同一个错误枚举的解读并不相同（例如 `InvalidData` 在
//! `set_client_status` 是「状态值非法」的 400，在 `rotate_secret` 是「Client
//! 不存在」的 404），因此这里保留四个独立的映射函数，而不是一个带分支的通用
//! 映射器。把映射从 async handler 里拆出来是为了让它成为纯函数：可以直接断言
//! 状态码与错误码，不需要数据库。
//!
//! 共同的约束只有一条：`QuotaExceeded` 是调用方可预期、可恢复的业务状态
//! （`clients::repository` 在配额检查处抛出），必须映射成带明确错误码的 4xx；
//! 只有真正的内部故障才允许收敛成 500（Issue #288）。
//!
//! 四个函数都逐个列出变体、不写 `_ =>` 兜底：新增错误变体时必须在这里显式表态，
//! 否则编译失败，避免又一个业务状态被静默归入 500。

use axum::response::Response;

use crate::{clients::service::ClientServiceError, error};

/// 配额超限的统一响应。
///
/// 用 409 而不是 403：同一业务条件在用户自助创建路径
/// （`users::oauth_client_handlers::create_owned_client`）已经是 409，
/// 两条路径对「配额用尽」给出不同状态码只会让调用方多写一套分支。
/// 403 在本项目里表示「凭据不具备该权限」，与配额无关。
fn quota_exceeded() -> Response {
    error::conflict(
        "quota_exceeded",
        "the OAuth client quota has been exhausted",
    )
}

/// 内部故障：留下可检索的结构化日志，对外只回笼统 500。
///
/// `Database` 变体取内层 sqlx 错误的文案：外层 `Display` 是固定的
/// 「could not persist client」，只记它会丢掉排障需要的驱动错误。两种文案都只进
/// 日志、不进响应体，也都不含凭据——`sqlx::Error` 的 `Display` 只描述驱动层失败，
/// 不携带绑定参数。
fn internal(error_value: &ClientServiceError, operation: &'static str) -> Response {
    let detail = match error_value {
        ClientServiceError::Database(database_error) => database_error.to_string(),
        other => other.to_string(),
    };
    tracing::error!(
        error = %detail,
        operation,
        "admin OAuth client operation failed"
    );
    error::internal()
}

/// 唯一键冲突：并发注册撞上同一 `client_id`，属于调用方可重试的业务状态。
fn is_unique_violation(database_error: &crate::sqlx::Error) -> bool {
    database_error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}

pub(super) fn create_client_error_response(error_value: &ClientServiceError) -> Response {
    match error_value {
        ClientServiceError::Validation(validation_error) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        ClientServiceError::QuotaExceeded => quota_exceeded(),
        ClientServiceError::Database(database_error) if is_unique_violation(database_error) => {
            error::conflict(
                "client_id_conflict",
                "client registration conflicts with existing data",
            )
        }
        ClientServiceError::Database(_)
        | ClientServiceError::SecretHash
        | ClientServiceError::InvalidData
        | ClientServiceError::SecretRotationConflict
        | ClientServiceError::AuditUnavailable
        | ClientServiceError::IdempotencyCorruptResult => internal(error_value, "create_client"),
        ClientServiceError::IdempotencyKeyInvalid => {
            error::bad_request("invalid_idempotency_key", "idempotency key is invalid")
        }
        ClientServiceError::IdempotencyConflict => error::conflict(
            "idempotency_conflict",
            "idempotency key was already used for a different request",
        ),
        ClientServiceError::IdempotencyKeyUnavailable => error::service_unavailable(
            "idempotency_key_unavailable",
            "the idempotency result cannot be recovered with the configured key ring",
        ),
    }
}

pub(super) fn update_client_error_response(error_value: &ClientServiceError) -> Response {
    match error_value {
        ClientServiceError::Validation(validation_error) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        ClientServiceError::QuotaExceeded => quota_exceeded(),
        ClientServiceError::Database(_)
        | ClientServiceError::SecretHash
        | ClientServiceError::InvalidData
        | ClientServiceError::SecretRotationConflict
        | ClientServiceError::AuditUnavailable
        | ClientServiceError::IdempotencyCorruptResult
        | ClientServiceError::IdempotencyKeyUnavailable
        | ClientServiceError::IdempotencyConflict
        | ClientServiceError::IdempotencyKeyInvalid => internal(error_value, "update_client"),
    }
}

pub(super) fn set_client_status_error_response(error_value: &ClientServiceError) -> Response {
    match error_value {
        ClientServiceError::InvalidData => {
            error::bad_request("invalid_status", "status is invalid")
        }
        ClientServiceError::QuotaExceeded => quota_exceeded(),
        ClientServiceError::Database(_)
        | ClientServiceError::Validation(_)
        | ClientServiceError::SecretHash
        | ClientServiceError::SecretRotationConflict
        | ClientServiceError::AuditUnavailable
        | ClientServiceError::IdempotencyCorruptResult
        | ClientServiceError::IdempotencyKeyUnavailable
        | ClientServiceError::IdempotencyConflict
        | ClientServiceError::IdempotencyKeyInvalid => internal(error_value, "set_client_status"),
    }
}

/// `rotate_secret` 的映射。
///
/// `SecretRotationConflict` 也在这里映射成 409，但 handler 会先行匹配该变体去写
/// 一条冲突审计——审计需要 `AppState` 且是异步的，不能塞进纯函数。审计写完后仍走
/// 这个函数取响应，保证两条路径的对外语义只有一份定义。
pub(super) fn rotate_secret_error_response(error_value: &ClientServiceError) -> Response {
    match error_value {
        ClientServiceError::InvalidData => {
            error::not_found("client_not_found", "client was not found")
        }
        ClientServiceError::QuotaExceeded => quota_exceeded(),
        ClientServiceError::SecretRotationConflict => error::conflict(
            "client_secret_rotation_conflict",
            "client secret was rotated by another concurrent request",
        ),
        ClientServiceError::Database(_)
        | ClientServiceError::SecretHash
        | ClientServiceError::Validation(_)
        | ClientServiceError::AuditUnavailable
        | ClientServiceError::IdempotencyCorruptResult => {
            internal(error_value, "rotate_client_secret")
        }
        ClientServiceError::IdempotencyKeyInvalid => {
            error::bad_request("invalid_idempotency_key", "idempotency key is invalid")
        }
        ClientServiceError::IdempotencyConflict => error::conflict(
            "idempotency_conflict",
            "idempotency key was already used for a different request",
        ),
        ClientServiceError::IdempotencyKeyUnavailable => error::service_unavailable(
            "idempotency_key_unavailable",
            "the idempotency result cannot be recovered with the configured key ring",
        ),
    }
}

#[cfg(test)]
#[path = "client_errors_tests.rs"]
mod tests;
