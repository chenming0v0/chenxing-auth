use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

use crate::{
    api::extract::{ApiJson, RequestIssuer, SessionRead, SessionWrite},
    audit::AuditEvent,
    error,
    integrations::cltermux::{types::CredentialBundle, validation::verify_inbound_token},
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        response::with_no_store_headers,
        token::decode_userinfo_token,
    },
    state::AppState,
    users::domain::{UserId, UserStatus},
};

use super::{
    LinkedAccountServiceError,
    pagination::{self, LinkedAccountListQuery},
    response,
};

#[derive(Debug, Serialize)]
struct ProviderList {
    items: Vec<crate::linked_accounts::service::AccountProviderView>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBindInput {
    pub public_key: String,
    pub private_key: String,
}

impl fmt::Debug for CredentialBindInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialBindInput")
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordInput {
    pub password: String,
}

impl fmt::Debug for PasswordInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordInput")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveInput {
    pub access_token: String,
}

impl fmt::Debug for ResolveInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveInput")
            .field("access_token", &"<redacted>")
            .finish()
    }
}

pub async fn account_providers(State(state): State<AppState>, _session: SessionRead) -> Response {
    with_no_store_headers(
        (
            StatusCode::OK,
            Json(ProviderList {
                items: state.linked_accounts.provider_descriptors(),
            }),
        )
            .into_response(),
    )
}

pub async fn list_linked_accounts(
    State(state): State<AppState>,
    session: SessionRead,
    query: Result<Query<LinkedAccountListQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return pagination::invalid_pagination(),
    };
    let limit = match pagination::limit(&query) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let cursor = match pagination::cursor(&query) {
        Ok(cursor) => cursor,
        Err(response) => return response,
    };
    match state.linked_accounts.list(session.user_id).await {
        Ok(items) => with_no_store_headers(pagination::page(items, limit, cursor.as_ref())),
        Err(error_value) => response::map_service_error(error_value),
    }
}

pub async fn get_linked_account(
    State(state): State<AppState>,
    session: SessionRead,
    Path(id): Path<String>,
) -> Response {
    match state.linked_accounts.find(session.user_id, &id).await {
        Ok(item) => with_no_store_headers((StatusCode::OK, Json(item)).into_response()),
        Err(error_value) => response::map_service_error(error_value),
    }
}

pub async fn bind_linked_account(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(provider): Path<String>,
    ApiJson(input): ApiJson<CredentialBindInput>,
) -> Response {
    if provider != "cltermux"
        || input.public_key.is_empty()
        || input.public_key.len() > 255
        || input.private_key.is_empty()
        || input.private_key.len() > 255
    {
        return error::bad_request("invalid_request", "the binding request is invalid");
    }
    let Some(credential) = session.user_session_credential() else {
        return error::unauthorized("invalid_session", "user session is invalid");
    };
    let result = state
        .linked_accounts
        .bind_cltermux(
            credential,
            CredentialBundle {
                public_key: input.public_key,
                private_key: input.private_key,
            },
            state.clock.now(),
        )
        .await;
    match result {
        Ok(item) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::CltermuxCredentialBind,
                    "linked_account".to_owned(),
                    Some(item.id.clone()),
                    serde_json::json!({"provider":"cltermux"}),
                ))
                .await;
            with_no_store_headers((StatusCode::CREATED, Json(item)).into_response())
        }
        Err(error_value) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::CltermuxCredentialBindFailure,
                    "linked_account".to_owned(),
                    Some("cltermux".to_owned()),
                    serde_json::json!({"code": response::service_code(&error_value)}),
                ))
                .await;
            response::map_service_error(error_value)
        }
    }
}

pub async fn refresh_linked_account(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(id): Path<String>,
) -> Response {
    match state
        .linked_accounts
        .refresh(session.user_id, &id, state.clock.now())
        .await
    {
        Ok(item) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::CltermuxCredentialRefresh,
                    "linked_account".to_owned(),
                    Some(id),
                    serde_json::json!({"result":"success"}),
                ))
                .await;
            with_no_store_headers((StatusCode::OK, Json(item)).into_response())
        }
        Err(error_value) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::CltermuxCredentialRefresh,
                    "linked_account".to_owned(),
                    Some(id),
                    serde_json::json!({"code": response::service_code(&error_value)}),
                ))
                .await;
            response::map_service_error(error_value)
        }
    }
}

pub async fn delete_linked_account(
    State(state): State<AppState>,
    session: SessionWrite,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<PasswordInput>,
) -> Response {
    let source_ip = crate::api::source_ip(None, &headers, &state.config.trusted_proxies);
    let authenticated = match state
        .users
        .reauthenticate_password(session.user_id, &input.password, source_ip.as_deref())
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) | Err(crate::users::service::UserServiceError::InvalidCredentials) => {
            return error::unauthorized("invalid_credentials", "password reauthentication failed");
        }
        Err(crate::users::service::UserServiceError::RateLimited) => {
            return error::too_many_requests(
                "password_reauthentication_rate_limited",
                "too many password reauthentication attempts; try again later",
            );
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "linked account password reauthentication failed");
            return error::internal();
        }
    };
    if authenticated.session_epoch != session.session.credential_generation().unwrap_or_default() {
        return error::unauthorized(
            "password_reauthentication_failed",
            "password reauthentication failed",
        );
    }
    match state.linked_accounts.delete(session.user_id, &id).await {
        Ok(()) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::ExternalIdentityUnlink,
                    "linked_account".to_owned(),
                    Some(id),
                    serde_json::json!({"provider":"cltermux"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error_value) => response::map_service_error(error_value),
    }
}

pub async fn resolve(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ResolveInput>,
) -> Response {
    let Some(config) = state.config.cltermux.as_ref() else {
        return error::unauthorized(
            "invalid_integration_credential",
            "integration credential is invalid",
        );
    };
    let Some(token) = bearer_token(&headers) else {
        return error::unauthorized(
            "invalid_integration_credential",
            "integration credential is invalid",
        );
    };
    if !verify_inbound_token(token, &config.inbound_token_digest) {
        return error::unauthorized(
            "invalid_integration_credential",
            "integration credential is invalid",
        );
    }
    if input.access_token.len() > 16 * 1024 {
        return error::bad_request("invalid_request", "the access token is invalid");
    }
    let claims =
        match decode_userinfo_token(&state.keys, issuer.issuer().as_str(), &input.access_token) {
            Ok(value) => value,
            Err(_) => return resolve_denied(&state, "invalid_chenxing_token").await,
        };
    match state.revocations.is_revoked(&input.access_token).await {
        Ok(false) => {}
        Ok(true) | Err(_) => return resolve_denied(&state, "invalid_chenxing_token").await,
    }
    if !config.allowed_client_ids.iter().any(|id| id == &claims.aud) {
        return resolve_denied(&state, "invalid_chenxing_token").await;
    }
    let presented = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let scopes = match effective_grant_scopes(&state, &claims.sub, &claims.aud, &presented).await {
        Ok(grant) => grant.scopes,
        Err(GrantGateError::Denied(_)) => {
            return resolve_denied(&state, "invalid_chenxing_token").await;
        }
        Err(GrantGateError::Unavailable(_)) => {
            return error::service_unavailable(
                "provider_unavailable",
                "authorization state is unavailable",
            );
        }
    };
    if !scopes.iter().any(|scope| scope == "cltermux:access") {
        return error::forbidden(
            "insufficient_scope",
            "the access token lacks the required scope",
        );
    }
    let Ok(user_id) = claims.sub.parse::<UserId>() else {
        return resolve_denied(&state, "invalid_chenxing_token").await;
    };
    match state.users.find_profile(user_id).await {
        Ok(Some(profile)) if UserStatus::parse(&profile.status) == Some(UserStatus::Active) => {}
        Ok(Some(_)) | Ok(None) => return resolve_denied(&state, "invalid_chenxing_token").await,
        Err(_) => {
            return error::service_unavailable("provider_unavailable", "user state is unavailable");
        }
    }
    let binding = match state.linked_accounts.resolve(user_id).await {
        Ok(value) => value,
        Err(LinkedAccountServiceError::NotFound) => {
            return error::not_found("account_not_linked", "the user has no linked account");
        }
        Err(error_value) => return response::map_service_error(error_value),
    };
    let now = state.clock.now();
    let token_exp = match OffsetDateTime::from_unix_timestamp(claims.exp as i64) {
        Ok(value) => value,
        Err(_) => return resolve_denied(&state, "invalid_chenxing_token").await,
    };
    let valid_until = token_exp.min(now + time::Duration::seconds(300));
    let body = crate::integrations::cltermux::contract::ResolveResponse {
        issuer: issuer.issuer().as_str().to_owned(),
        subject: claims.sub,
        client_id: claims.aud,
        scope: scopes.join(" "),
        provider: "cltermux".to_owned(),
        uid: binding.uid,
        binding_id: binding.binding_id,
        binding_version: binding.binding_version,
        resolved_at: now,
        valid_until,
    };
    with_no_store_headers((StatusCode::OK, Json(body)).into_response())
}

async fn resolve_denied(state: &AppState, code: &'static str) -> Response {
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "integration".to_owned(),
            None,
            crate::audit::AuditAction::CltermuxResolveDenied,
            "linked_account".to_owned(),
            None,
            serde_json::json!({"code":code}),
        ))
        .await;
    error::unauthorized(code, "the Chenxing access token is invalid")
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token)
        .filter(|token| !token.is_empty())
}
