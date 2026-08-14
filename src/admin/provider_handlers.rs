use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    admin::{authorization::AdminActor, domain::AdminPermission},
    api::extract::{AdminRead, AdminWrite, RequestIssuer},
    audit::AuditEvent,
    error,
    oauth::providers::{domain::ProviderInput, service::ExternalOAuthError},
    state::AppState,
};

#[derive(Debug, serde::Serialize)]
struct ProviderSummaryResponse {
    #[serde(flatten)]
    provider: crate::oauth::providers::domain::ProviderSummary,
    callback_uri: String,
}

fn provider_response(
    issuer: &RequestIssuer,
    provider: crate::oauth::providers::domain::ProviderSummary,
) -> ProviderSummaryResponse {
    ProviderSummaryResponse {
        callback_uri: format!(
            "{}/auth/external/{}/callback",
            issuer.issuer().as_str(),
            provider.slug
        ),
        provider,
    }
}

#[derive(Debug, Deserialize)]
pub struct ProviderStatusPath {
    pub slug: String,
}

pub async fn list_providers(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    admin: AdminRead,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        return response;
    }
    match state.external_oauth.list().await {
        Ok(providers) => (
            StatusCode::OK,
            Json(
                providers
                    .into_iter()
                    .map(|provider| provider_response(&issuer, provider))
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list external OAuth providers");
            error::internal()
        }
    }
}

pub async fn create_provider(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    admin: AdminWrite,
    Json(input): Json<ProviderInput>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if input.client_secret.as_deref().is_none_or(str::is_empty) {
        return error::bad_request(
            "invalid_oauth_provider",
            "client_secret is required when creating a provider",
        );
    }
    match state.external_oauth.create(input.clone()).await {
        Ok(provider) => {
            record_provider_event(
                &state,
                actor,
                crate::audit::AuditAction::OauthProviderCreate,
                &provider.slug,
                serde_json::json!({
                    "authorization_endpoint": input.authorization_endpoint,
                    "token_endpoint": input.token_endpoint,
                    "userinfo_endpoint": input.userinfo_endpoint,
                }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(provider_response(&issuer, provider)),
            )
                .into_response()
        }
        Err(error_value) => provider_error_response(error_value, "create_provider"),
    }
}

pub async fn update_provider(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(slug): Path<String>,
    Json(input): Json<ProviderInput>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if input.slug != slug {
        return error::bad_request("invalid_oauth_provider", "provider slug cannot be changed");
    }
    match state.external_oauth.update(&slug, input.clone()).await {
        Ok(true) => {
            record_provider_event(
                &state,
                actor,
                crate::audit::AuditAction::OauthProviderUpdate,
                &slug,
                serde_json::json!({
                    "authorization_endpoint": input.authorization_endpoint,
                    "token_endpoint": input.token_endpoint,
                    "userinfo_endpoint": input.userinfo_endpoint,
                }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("oauth_provider_not_found", "provider was not found"),
        Err(error_value) => provider_error_response(error_value, "update_provider"),
    }
}

pub async fn enable_provider(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(slug): Path<String>,
) -> Response {
    set_provider_status(&state, &admin, &slug, "active").await
}

pub async fn disable_provider(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(slug): Path<String>,
) -> Response {
    set_provider_status(&state, &admin, &slug, "disabled").await
}

/// 启用/停用的公共实现。授权由调用点传入的 `AdminWrite` 完成，
/// 因此 CSRF 与权限校验仍然只有一条路径。
async fn set_provider_status(
    state: &AppState,
    admin: &AdminWrite,
    slug: &str,
    status: &str,
) -> Response {
    let actor = match admin
        .authorize(state, AdminPermission::ManageIdentityProviders)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state.external_oauth.set_status(slug, status).await {
        Ok(true) => {
            record_provider_event(
                state,
                actor,
                match status {
                    "active" => crate::audit::AuditAction::OauthProviderActive,
                    "disabled" => crate::audit::AuditAction::OauthProviderDisabled,
                    _ => unreachable!("provider status is validated by the service"),
                },
                slug,
                serde_json::json!({"result": "success"}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("oauth_provider_not_found", "provider was not found"),
        Err(error_value) => provider_error_response(error_value, "set_provider_status"),
    }
}

/// `ExternalOAuthError` → HTTP 响应的统一映射。
///
/// 变体逐个显式列出、不写 `_` 兜底（与 `client_errors.rs` 同一约定）：新增错误
/// 变体时必须在这里显式表态，否则编译失败，避免业务状态被静默归入 500。
/// `MissingSecret`/`RemoteRequest`/`InvalidUserInfo`/`EmailNotVerified`/
/// `EmailAlreadyRegistered`/`UserDisabled`/`OwnerBootstrapRequired` 只在外部登录
/// 流程产生，admin CRUD 路径返回它们说明调用链出错，统一按内部故障处理并留下
/// 结构化日志。
fn provider_error_response(error_value: ExternalOAuthError, operation: &'static str) -> Response {
    match &error_value {
        ExternalOAuthError::Validation(validation_error) => {
            error::bad_request("invalid_oauth_provider", validation_error.to_string())
        }
        ExternalOAuthError::NotFound | ExternalOAuthError::Disabled => {
            error::not_found("oauth_provider_not_found", "provider was not found")
        }
        ExternalOAuthError::Database(database_error)
            if database_error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == "23505") =>
        {
            error::conflict(
                "oauth_provider_conflict",
                "provider slug is already registered",
            )
        }
        ExternalOAuthError::Database(_)
        | ExternalOAuthError::Secret(_)
        | ExternalOAuthError::MissingSecret
        | ExternalOAuthError::RemoteRequest
        | ExternalOAuthError::InvalidUserInfo
        | ExternalOAuthError::EmailNotVerified
        | ExternalOAuthError::EmailAlreadyRegistered
        | ExternalOAuthError::UserDisabled
        | ExternalOAuthError::OwnerBootstrapRequired => internal(&error_value, operation),
    }
}

/// 内部故障：留下可检索的结构化日志，对外只回笼统 500。
///
/// `ExternalOAuthError` 的 `Display` 已包含内层细节（如 sqlx 驱动错误），直接
/// 记录即可，不需要逐变体拆包；日志不含凭据。
fn internal(error_value: &ExternalOAuthError, operation: &'static str) -> Response {
    tracing::error!(
        error = %error_value,
        operation,
        "admin external OAuth provider operation failed"
    );
    error::internal()
}

async fn record_provider_event(
    state: &AppState,
    actor: AdminActor,
    action: crate::audit::AuditAction,
    slug: &str,
    details: serde_json::Value,
) {
    let (actor_type, actor_id) = actor.audit_fields();
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            action,
            "oauth_provider".to_owned(),
            Some(slug.to_owned()),
            details,
        ))
        .await;
}
