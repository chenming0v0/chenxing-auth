use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;

use crate::{
    api::extract::{ApiJson, SessionRead, SessionWrite},
    audit::AuditEvent,
    clients::{
        domain::ClientRegistrationInput,
        service::{
            ClientRegistrationRequest, ClientServiceError, ClientSummary, RegisteredClientSecret,
        },
    },
    error,
    oauth::quota::QuotaSnapshot,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct OwnedClientResponse {
    id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    status: String,
    quota: QuotaSnapshot,
}

#[derive(Serialize)]
struct RegisteredOwnedClientResponse {
    #[serde(flatten)]
    client: OwnedClientResponse,
    /// Client 认证方式；`none` 表示公开客户端，响应不含 client_secret。
    auth_method: &'static str,
    /// 公开客户端（SPA / 移动端）不签发 secret，此时该字段整体省略（Issue #66）。
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

impl fmt::Debug for RegisteredOwnedClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredOwnedClientResponse")
            .field("client", &self.client)
            .field("auth_method", &self.auth_method)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct OwnedClientListResponse {
    items: Vec<OwnedClientResponse>,
    /// 当前用户拥有的 Client 总数（不随分页变化），供前端渲染分页与「还有更多」提示。
    total: i64,
}

/// list_owned_clients 专用查询参数，与管理端 `ClientListQuery` 一致（Issue #415）。
#[derive(Debug, Deserialize)]
pub struct OwnedClientListQuery {
    /// 返回条数，默认 200，最大 200，超限自动 clamp。
    pub limit: Option<i64>,
    /// 跳过条数，默认 0，用于手动翻页。
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AuthorizedAppListResponse {
    items: Vec<crate::consents::AuthorizedApp>,
}

pub async fn list_owned_clients(
    State(state): State<AppState>,
    session: SessionRead,
    Query(query): Query<OwnedClientListQuery>,
) -> Response {
    let effective = match state.plans.effective_plan_for_user(session.user_id).await {
        Ok(effective) => effective,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load plan for owned OAuth client quota");
            return error::internal();
        }
    };
    // 读路径不设闸门：没有生效套餐时照常列出既有 Client，配额上限留空。
    let quota_limits = effective.map(|effective| effective.plan.auth_quota_limits());
    // 分页 + 总数：超过 200 个 Client 时不再静默截断，翻页即可访问全部（Issue #415）。
    let (clients, total) = match state
        .clients
        .list_for_user(session.user_id, query.limit, query.offset)
        .await
    {
        Ok(result) => result,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list owned OAuth clients");
            return error::internal();
        }
    };
    match add_quota(&state, clients, quota_limits).await {
        Ok(items) => (
            StatusCode::OK,
            Json(OwnedClientListResponse { items, total }),
        )
            .into_response(),
        Err(response) => response,
    }
}

pub async fn list_authorized_apps(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.consents.list_for_user(session.user_id).await {
        Ok(items) => (StatusCode::OK, Json(AuthorizedAppListResponse { items })).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list authorized OAuth apps");
            error::internal()
        }
    }
}

pub async fn revoke_authorized_app(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    // 撤销审计需要请求上下文（源 IP / UA），供安全日志详情展示（Issue #308）。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    // Issue #65 原子性修复：将撤销的权威写入（DB）与缓存失效（Redis）顺序调整，
    // 使 DB 成为单一原子事实，Redis 成为 best-effort 缓存。
    //
    // 修复前：先 Redis 再 DB，DB 失败时 Redis 已写入，导致状态分裂。
    // 修复后：先 DB（原子 UPDATE）再 Redis（best-effort），DB 失败时无副作用。
    let revoked = match state
        .consents
        .revoke_for_user(session.user_id, &client_id)
        .await
    {
        Ok(revoked) => revoked,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke OAuth consent in DB");
            return error::internal();
        }
    };
    // 记录不存在或已撤销：幂等返回 204
    let Some(state_version) = revoked else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Issue #418：撤销必须销毁凭据，而不是只留一条 consent 记录等下一次兑换被
    // 挡住。check-on-use 的问题是它把「断开」变成「赌 AT 的剩余寿命，并指望
    // 每条兑换路径都记得查 consent」。这里按 grant 删掉全部 Refresh Token。
    //
    // 顺序在 DB 撤销之后：DB 是权威事实，先删凭据再写 DB 会在 DB 失败时留下
    // 「凭据没了但授权还在」的状态。反过来则只是清理滞后，下一次撤销或
    // 兑换检查仍会兜住。
    let revoked_tokens = match state
        .refresh_tokens
        .revoke_grant_tokens(&session.user_id.to_string(), &client_id)
        .await
    {
        Ok(revoked_tokens) => Some(revoked_tokens),
        Err(error_value) => {
            // 不回 500：DB 撤销已经生效，consent 检查仍会拒绝这些凭据的兑换。
            // 但这属于「撤销没有完全落地」，必须留下可检索的证据。
            tracing::error!(
                error = %error_value,
                user_id = %session.user_id,
                client_id = %client_id,
                "failed to destroy refresh tokens after OAuth consent revocation; \
                 the grant stays revoked in the database and exchanges remain blocked"
            );
            None
        }
    };
    // DB 写入成功，尝试写入 Redis 缓存结论（best-effort）。
    //
    // Issue #276：必须带上这次撤销的 `state_version`。缓存更新是版本化条件写，
    // 如果用户在这两步之间已经重新授权（DB 版本更高），本次写入会被拒绝，
    // 从而不会留下一个否决数据库新状态的陈旧撤销标记。被拒绝不是错误。
    if let Err(error_value) = state
        .revocations
        .revoke_consent(&session.user_id.to_string(), &client_id, state_version)
        .await
    {
        tracing::warn!(
            error = %error_value,
            user_id = %session.user_id,
            client_id = %client_id,
            "failed to invalidate OAuth consent revocation cache, will fall back to DB on next check"
        );
        // Redis 失效失败不影响正确性（DB 已是权威真相，缓存未命中会回源），
        // 仅 warn 不返回 500。
    }
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            Some(session.user_id.to_string()),
            crate::audit::AuditAction::ConsentRevoke,
            "oauth_consent".to_owned(),
            Some(client_id),
            crate::audit::with_request_context(
                // 凭据清理结果进审计（Issue #418 验收项）：`null` 表示清理未能
                // 完成，撤销事实仍然成立，但需要人工确认残留。
                serde_json::json!({
                    "result": "success",
                    "revoked_refresh_tokens": revoked_tokens,
                }),
                source_ip.as_deref(),
                user_agent.as_deref(),
            ),
        ))
        .await;
    StatusCode::NO_CONTENT.into_response()
}

fn self_service_disabled() -> Response {
    error::forbidden(
        "self_service_disabled",
        "平台当前未开放自助接入，请联系管理员。",
    )
}

pub async fn create_owned_client(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(input): ApiJson<ClientRegistrationRequest>,
) -> Response {
    match state.plans.effective_plan_for_user(session.user_id).await {
        // 这里只做快速闸门和保持既有错误优先级；repository 会在用户行锁后重新解析
        // 并锁定权威套餐，绝不消费这个事务外快照（Issue #479）。
        Ok(Some(_)) => {}
        // 自助接入闸门：没有生效套餐时不允许新建 Client，但既有 Client 的
        // 授权、令牌和列表路径不受影响。
        Ok(None) => return self_service_disabled(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load plan for OAuth client quota");
            return error::internal();
        }
    }
    match state
        .clients
        .register_for_user(session.user_id, input)
        .await
    {
        Ok(Some(registered)) => {
            match owned_registered_response(
                &state,
                registered.client,
                Some(registered.quota_limits),
            )
            .await
            {
                Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
                Err(response) => response,
            }
        }
        // 套餐可能在快速闸门之后被归档或取消默认；事务内结果才是权威。
        Ok(None) => self_service_disabled(),
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::QuotaExceeded) => error::conflict(
            "oauth_client_quota_exceeded",
            "the current plan's OAuth application quota has been exceeded",
        ),
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to create owned OAuth client");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
    }
}

pub async fn update_owned_client(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
    ApiJson(input): ApiJson<ClientRegistrationInput>,
) -> Response {
    match state
        .clients
        .update_for_user(session.user_id, &client_id, input)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update owned OAuth client");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
    }
}

pub async fn disable_owned_client(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    set_owned_client_status(state, session, client_id, "disabled").await
}

pub async fn enable_owned_client(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    set_owned_client_status(state, session, client_id, "active").await
}

async fn set_owned_client_status(
    state: AppState,
    session: SessionWrite,
    client_id: String,
    status: &str,
) -> Response {
    match state
        .clients
        .set_status_for_user(session.user_id, &client_id, status)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(ClientServiceError::InvalidData) => {
            error::bad_request("invalid_status", "status is invalid")
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update owned OAuth client status");
            error::internal()
        }
        Err(
            ClientServiceError::Validation(_)
            | ClientServiceError::SecretHash
            | ClientServiceError::QuotaExceeded
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
    }
}

pub async fn rotate_owned_client_secret(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    match state
        .clients
        .rotate_secret_for_user(session.user_id, &client_id)
        .await
    {
        Ok(secret) => {
            if state
                .audit
                .record_blocking(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::ClientSecretRotate,
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            (StatusCode::OK, Json(secret)).into_response()
        }
        Err(ClientServiceError::InvalidData) => {
            error::not_found("oauth_client_not_found", "OAuth project was not found")
        }
        Err(ClientServiceError::SecretRotationConflict) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::ClientSecretRotateConflict,
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({
                        "result": "conflict",
                        "reason": "concurrent_rotation"
                    }),
                ))
                .await;
            error::conflict(
                "client_secret_rotation_conflict",
                "client secret was rotated by another concurrent request",
            )
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to rotate owned OAuth client secret");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::Validation(_)
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
    }
}

async fn add_quota(
    state: &AppState,
    clients: Vec<ClientSummary>,
    quota_limits: Option<crate::plans::domain::AuthQuotaLimits>,
) -> Result<Vec<OwnedClientResponse>, Response> {
    let mut items = Vec::with_capacity(clients.len());
    for client in clients {
        let quota = state
            .oauth_quotas
            .snapshot_at(&client.client_id, quota_limits, state.clock.now())
            .await
            .map_err(|_| error::internal())?;
        items.push(OwnedClientResponse {
            id: client.id,
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            status: client.status,
            quota,
        });
    }
    Ok(items)
}

async fn owned_registered_response(
    state: &AppState,
    client: RegisteredClientSecret,
    quota_limits: Option<crate::plans::domain::AuthQuotaLimits>,
) -> Result<RegisteredOwnedClientResponse, Response> {
    let quota = state
        .oauth_quotas
        .snapshot_at(&client.client_id, quota_limits, state.clock.now())
        .await
        .map_err(|_| error::internal())?;
    Ok(RegisteredOwnedClientResponse {
        client: OwnedClientResponse {
            id: client.id,
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            status: "active".to_owned(),
            quota,
        },
        auth_method: client.auth_method.as_str(),
        client_secret: client.client_secret,
    })
}
