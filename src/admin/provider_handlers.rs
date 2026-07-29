use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    admin::{
        authorization::{current_admin_mutation, current_admin_permission},
        domain::AdminPermission,
    },
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
    state: &AppState,
    provider: crate::oauth::providers::domain::ProviderSummary,
) -> ProviderSummaryResponse {
    ProviderSummaryResponse {
        callback_uri: format!(
            "{}/auth/external/{}/callback",
            state.config.issuer_url, provider.slug
        ),
        provider,
    }
}

#[derive(Debug, Deserialize)]
pub struct ProviderStatusPath {
    pub slug: String,
}

pub async fn list_providers(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageIdentityProviders).await
    {
        return response;
    }
    match state.external_oauth.list().await {
        Ok(providers) => (
            StatusCode::OK,
            Json(
                providers
                    .into_iter()
                    .map(|provider| provider_response(&state, provider))
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
    headers: HeaderMap,
    Json(input): Json<ProviderInput>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageIdentityProviders)
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
    match state.external_oauth.create(input).await {
        Ok(provider) => {
            record_provider_event(&state, actor, "oauth_provider_create", &provider.slug).await;
            (
                StatusCode::CREATED,
                Json(provider_response(&state, provider)),
            )
                .into_response()
        }
        Err(error_value) => provider_error_response(error_value),
    }
}

pub async fn update_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(input): Json<ProviderInput>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageIdentityProviders)
            .await
        {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if input.slug != slug {
        return error::bad_request("invalid_oauth_provider", "provider slug cannot be changed");
    }
    match state.external_oauth.update(&slug, input).await {
        Ok(true) => {
            record_provider_event(&state, actor, "oauth_provider_update", &slug).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::bad_request("oauth_provider_not_found", "provider was not found"),
        Err(error_value) => provider_error_response(error_value),
    }
}

pub async fn enable_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    set_provider_status(state, headers, slug, "active").await
}

pub async fn disable_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    set_provider_status(state, headers, slug, "disabled").await
}

async fn set_provider_status(
    state: AppState,
    headers: HeaderMap,
    slug: String,
    status: &str,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageIdentityProviders)
            .await
        {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    match state.external_oauth.set_status(&slug, status).await {
        Ok(true) => {
            record_provider_event(&state, actor, &format!("oauth_provider_{status}"), &slug).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::bad_request("oauth_provider_not_found", "provider was not found"),
        Err(error_value) => provider_error_response(error_value),
    }
}

fn provider_error_response(error_value: ExternalOAuthError) -> Response {
    match error_value {
        ExternalOAuthError::Validation(validation_error) => {
            error::bad_request("invalid_oauth_provider", validation_error.to_string())
        }
        ExternalOAuthError::NotFound | ExternalOAuthError::Disabled => {
            error::bad_request("oauth_provider_not_found", "provider was not found")
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
        ExternalOAuthError::Database(database_error) => {
            tracing::error!(error = %database_error, "external OAuth provider database operation failed");
            error::internal()
        }
        ExternalOAuthError::Secret(secret_error) => {
            tracing::error!(error = %secret_error, "external OAuth provider secret operation failed");
            error::internal()
        }
        _ => error::internal(),
    }
}

async fn record_provider_event(
    state: &AppState,
    actor: super::authorization::AdminActor,
    action: &str,
    slug: &str,
) {
    let (actor_type, actor_id) = actor.audit_fields();
    state
        .audit
        .record(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            action.to_owned(),
            "oauth_provider".to_owned(),
            Some(slug.to_owned()),
            serde_json::json!({"result": "success"}),
        ))
        .await;
}
