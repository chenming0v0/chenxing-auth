//! 头像上传、读取与移除。
//!
//! 上传体是原始图片字节而不是 multipart：客户端只发一个文件，multipart 只会多引入
//! 一层解析器和一个新的 axum feature，收益为零。声明的 `Content-Type` 一律不参与
//! 格式判定，格式只由 [`crate::users::avatar_image`] 按字节魔数决定。

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use super::avatar_image::{AvatarImageError, MAX_UPLOAD_BYTES, MIN_SOURCE_EDGE};
use super::service::AvatarServiceError;
use super::ui_handlers::profile_response;
use crate::{
    api::extract::{SessionRead, SessionWrite},
    audit::AuditEvent,
    error,
    state::AppState,
};

/// 允许直出的头像 MIME 白名单。
///
/// 落库值只可能来自规范化流程，但服务路径仍按白名单回读：数据库若被旁路写入，
/// 该白名单是「浏览器不会把用户字节当 HTML 解析」的最后一道闸。
const SERVABLE_MIME: [&str; 1] = [super::avatar_image::STORED_MIME];

/// `PUT /api/v1/auth/me/avatar`
///
/// `SessionWrite` 在请求体解析之前完成 Session + CSRF 校验，未授权的上传字节
/// 不会进入图片解码器。`Bytes` 必须是最后一个参数：它消耗请求体，放在提取器
/// 序列中间无法编译。
pub async fn upload_current_user_avatar(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    body: Bytes,
) -> Response {
    let byte_count = body.len();
    // 头像变更是账户资料操作，审计记录请求上下文（源 IP / UA，Issue #308）。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    match state
        .users
        .update_avatar(session.user_id, body.to_vec())
        .await
    {
        Ok(Some(profile)) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    "user_avatar_update".to_owned(),
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::with_request_context(
                        serde_json::json!({"result": "success", "upload_bytes": byte_count}),
                        source_ip.as_deref(),
                        user_agent.as_deref(),
                    ),
                ))
                .await;
            profile_response(&session, profile)
        }
        Ok(None) => error::unauthorized("invalid_session", "user session is invalid"),
        Err(error_value) => avatar_error(error_value),
    }
}

/// `DELETE /api/v1/auth/me/avatar`：移除头像，前端回落到首字母占位符。
pub async fn delete_current_user_avatar(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    match state.users.clear_avatar(session.user_id).await {
        Ok(Some(profile)) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    "user_avatar_remove".to_owned(),
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::with_request_context(
                        serde_json::json!({"result": "success"}),
                        source_ip.as_deref(),
                        user_agent.as_deref(),
                    ),
                ))
                .await;
            profile_response(&session, profile)
        }
        Ok(None) => error::unauthorized("invalid_session", "user session is invalid"),
        Err(error_value) => avatar_error(error_value),
    }
}

/// `GET /api/v1/auth/me/avatar`：返回本人头像字节。
///
/// 只服务当前会话自己的头像，不接受路径上的用户 ID：按 ID 直取会把「该用户是否
/// 存在、是否设过头像」变成一个无需认证即可探测的信号。
///
/// 缓存必须是 `private`：响应随会话变化，任何共享缓存留存它都等于跨用户泄露。
pub async fn current_user_avatar(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.users.find_avatar(session.user_id).await {
        Ok(Some(avatar)) => {
            let content_type = SERVABLE_MIME
                .iter()
                .find(|allowed| **allowed == avatar.mime.as_str())
                .copied()
                .unwrap_or("application/octet-stream");
            let mut response = (StatusCode::OK, avatar.bytes).into_response();
            let response_headers = response.headers_mut();
            response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            response_headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=300"),
            );
            // 版本号已在 URL 查询参数里，ETag 让未变更的重复请求走 304。
            if let Ok(etag) =
                HeaderValue::from_str(&format!("\"{}\"", avatar.updated_at.unix_timestamp_nanos()))
            {
                response_headers.insert(header::ETAG, etag);
            }
            response
        }
        Ok(None) => error::not_found("avatar_not_found", "no avatar is set"),
        Err(error_value) => avatar_error(error_value),
    }
}

/// 把服务层错误映射成协议错误。
///
/// 校验类失败必须给出可判别的 code，前端据此提示「换一张更大的图」而不是笼统的
/// 「请求失败」；解码失败不回显任何解码器内部信息。
fn avatar_error(error_value: AvatarServiceError) -> Response {
    let image_error = match error_value {
        AvatarServiceError::Image(image_error) => image_error,
        other => {
            tracing::error!(error = %other, "failed to process user avatar");
            return error::internal();
        }
    };
    match image_error {
        AvatarImageError::Empty => error::bad_request("avatar_empty", "avatar upload is empty"),
        AvatarImageError::TooLarge => error::bad_request(
            "avatar_too_large",
            format!(
                "avatar must be at most {} MiB",
                MAX_UPLOAD_BYTES / (1024 * 1024)
            ),
        ),
        AvatarImageError::UnsupportedFormat => error::bad_request(
            "avatar_unsupported_format",
            "avatar must be a PNG, JPEG or WebP image",
        ),
        AvatarImageError::Undecodable => {
            error::bad_request("avatar_undecodable", "avatar image could not be read")
        }
        AvatarImageError::TooSmall => error::bad_request(
            "avatar_too_small",
            format!("avatar must be at least {MIN_SOURCE_EDGE}x{MIN_SOURCE_EDGE} pixels"),
        ),
        AvatarImageError::EncodeFailed => {
            tracing::error!("avatar re-encode failed");
            error::internal()
        }
    }
}
