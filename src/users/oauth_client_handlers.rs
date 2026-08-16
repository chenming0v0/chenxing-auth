use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    api::extract::{ApiJson, SessionRead, SessionWrite},
    audit::AuditEvent,
    clients::{
        domain::ClientRegistrationInput,
        idempotency::IdempotencyKey,
        service::{ClientRegistrationRequest, ClientServiceError, ClientSummary},
    },
    error,
    state::AppState,
};
#[path = "oauth_client_responses.rs"]
mod oauth_client_responses;
use oauth_client_responses::{OwnedClientResponse, owned_registered_response};

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
    match crate::oauth::revoke_consent_use_case::revoke_consent(
        crate::oauth::revoke_consent_use_case::RevokeConsentServices {
            consents: &state.consents,
            refresh_tokens: &state.refresh_tokens,
            revocations: &state.revocations,
            audit: &state.audit,
        },
        session.user_id,
        &client_id,
        source_ip.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke OAuth consent in DB");
            error::internal()
        }
    }
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
    headers: HeaderMap,
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
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(key) => key,
        Err(()) => {
            return error::bad_request("invalid_idempotency_key", "idempotency key is invalid");
        }
    };
    let actor_id = session.user_id.to_string();
    let result = match idempotency_key {
        Some(key) => state
            .clients
            .register_for_user_with_audit_idempotent(
                session.user_id,
                input,
                format!("user:{}", session.user_id),
                key,
                move |client| {
                    AuditEvent::new(
                        "user".to_owned(),
                        Some(actor_id.clone()),
                        crate::audit::AuditAction::ClientCreate,
                        "oauth_client".to_owned(),
                        Some(client.client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    )
                },
            )
            .await
            // 幂等恢复路径没有随行的事务内套餐快照；配额强制已在幂等插入
            // 事务内完成（Issue #479/#50），这里稍后只补取展示用的限额。
            .map(|client| Some((client, None))),
        None => state
            .clients
            .register_for_user_with_audit(session.user_id, input, move |client| {
                AuditEvent::new(
                    "user".to_owned(),
                    Some(actor_id.clone()),
                    crate::audit::AuditAction::ClientCreate,
                    "oauth_client".to_owned(),
                    Some(client.client_id.clone()),
                    serde_json::json!({"result": "success"}),
                )
            })
            .await
            .map(|registered| registered.map(|owned| (owned.client, Some(owned.quota_limits)))),
    };
    match result {
        Ok(Some((client, quota_limits))) => {
            let quota_limits = match quota_limits {
                Some(limits) => Some(limits),
                None => state
                    .plans
                    .effective_plan_for_user(session.user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|effective| effective.plan.auth_quota_limits()),
            };
            match owned_registered_response(&state, client, quota_limits).await {
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
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
        Err(ClientServiceError::IdempotencyKeyInvalid) => {
            error::bad_request("invalid_idempotency_key", "idempotency key is invalid")
        }
        Err(ClientServiceError::IdempotencyConflict) => error::conflict(
            "idempotency_conflict",
            "idempotency key was already used for a different request",
        ),
        Err(ClientServiceError::IdempotencyKeyUnavailable) => error::service_unavailable(
            "idempotency_key_unavailable",
            "the idempotency result cannot be recovered with the configured key ring",
        ),
        Err(ClientServiceError::IdempotencyCorruptResult) => error::internal(),
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
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
        Err(
            ClientServiceError::IdempotencyKeyInvalid
            | ClientServiceError::IdempotencyConflict
            | ClientServiceError::IdempotencyKeyUnavailable
            | ClientServiceError::IdempotencyCorruptResult,
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
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(
            ClientServiceError::Validation(_)
            | ClientServiceError::SecretHash
            | ClientServiceError::QuotaExceeded
            | ClientServiceError::SecretRotationConflict,
        ) => error::internal(),
        Err(
            ClientServiceError::IdempotencyKeyInvalid
            | ClientServiceError::IdempotencyConflict
            | ClientServiceError::IdempotencyKeyUnavailable
            | ClientServiceError::IdempotencyCorruptResult,
        ) => error::internal(),
    }
}

pub async fn rotate_owned_client_secret(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(key) => key,
        Err(()) => {
            return error::bad_request("invalid_idempotency_key", "idempotency key is invalid");
        }
    };
    let actor_id = session.user_id.to_string();
    let result = match idempotency_key {
        Some(key) => {
            state
                .clients
                .rotate_secret_for_user_with_audit_idempotent(
                    session.user_id,
                    &client_id,
                    format!("user:{}", session.user_id),
                    key,
                    AuditEvent::new(
                        "user".to_owned(),
                        Some(actor_id),
                        crate::audit::AuditAction::ClientSecretRotate,
                        "oauth_client".to_owned(),
                        Some(client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    ),
                )
                .await
        }
        None => {
            state
                .clients
                .rotate_secret_for_user_with_audit(
                    session.user_id,
                    &client_id,
                    AuditEvent::new(
                        "user".to_owned(),
                        Some(actor_id),
                        crate::audit::AuditAction::ClientSecretRotate,
                        "oauth_client".to_owned(),
                        Some(client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    ),
                )
                .await
        }
    };
    match result {
        Ok(secret) => (StatusCode::OK, Json(secret)).into_response(),
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
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::Validation(_)
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
        Err(ClientServiceError::IdempotencyKeyInvalid) => {
            error::bad_request("invalid_idempotency_key", "idempotency key is invalid")
        }
        Err(ClientServiceError::IdempotencyConflict) => error::conflict(
            "idempotency_conflict",
            "idempotency key was already used for a different request",
        ),
        Err(ClientServiceError::IdempotencyKeyUnavailable) => error::service_unavailable(
            "idempotency_key_unavailable",
            "the idempotency result cannot be recovered with the configured key ring",
        ),
        Err(ClientServiceError::IdempotencyCorruptResult) => error::internal(),
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

fn parse_idempotency_key(headers: &HeaderMap) -> Result<Option<IdempotencyKey>, ()> {
    let Some(value) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    IdempotencyKey::parse(value).map(Some).map_err(|_| ())
}
