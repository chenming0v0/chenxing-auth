use crate::{
    api::{
        extract::{ApiJson, SessionRead, SessionWrite},
        source_ip,
    },
    audit::AuditEvent,
    error,
    oauth::providers::{domain::is_valid_provider_slug, service::ExternalIdentityUnlinkError},
    state::AppState,
    users::service::UserServiceError,
};
use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};

#[derive(Debug, Serialize)]
struct LinkedIdentity {
    provider: String,
    provider_name: String,
    email: String,
    #[serde(with = "time::serde::rfc3339")]
    linked_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct LinkedIdentityList {
    items: Vec<LinkedIdentity>,
}

pub async fn list_linked_identities(
    State(state): State<AppState>,
    session: SessionRead,
) -> Response {
    match state.external_oauth.list_identities(session.user_id).await {
        Ok(items) => (
            StatusCode::OK,
            Json(LinkedIdentityList {
                items: items
                    .into_iter()
                    .map(|item| LinkedIdentity {
                        provider: item.provider_slug,
                        provider_name: item.provider_name,
                        email: item.email,
                        linked_at: item.created_at,
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list linked external identities");
            error::internal()
        }
    }
}

#[derive(Deserialize)]
pub struct UnlinkInput {
    pub password: String,
}

impl fmt::Debug for UnlinkInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlinkInput")
            .field("password", &"<redacted>")
            .finish()
    }
}

pub async fn unlink_external_identity(
    State(state): State<AppState>,
    session: SessionWrite,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    ApiJson(input): ApiJson<UnlinkInput>,
) -> Response {
    if !is_valid_provider_slug(&slug) {
        return error::not_found(
            "oauth_identity_not_found",
            "linked external identity was not found",
        );
    }
    let source_ip = source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let authenticated = match state
        .users
        .reauthenticate_password(session.user_id, &input.password, source_ip.as_deref())
        .await
    {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) | Err(UserServiceError::InvalidCredentials) => {
            return error::unauthorized("invalid_credentials", "password reauthentication failed");
        }
        Err(UserServiceError::RateLimited) => {
            return error::too_many_requests(
                "password_reauthentication_rate_limited",
                "too many password reauthentication attempts; try again later",
            );
        }
        Err(UserServiceError::SourceIpUnavailable) => return error::internal(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "password reauthentication failed unexpectedly");
            return error::internal();
        }
    };
    match state
        .external_oauth
        .unlink_identity(session.user_id, authenticated.session_epoch, &slug)
        .await
    {
        Ok(crate::oauth::providers::repository::UnlinkIdentityOutcome::Removed) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::ExternalIdentityUnlink,
                    "external_identity".to_owned(),
                    Some(slug),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(crate::oauth::providers::repository::UnlinkIdentityOutcome::Missing) => {
            error::not_found(
                "oauth_identity_not_found",
                "linked external identity was not found",
            )
        }
        Ok(crate::oauth::providers::repository::UnlinkIdentityOutcome::LastCredential) => {
            error::conflict(
                "oauth_last_login_credential",
                "cannot unlink the last usable login credential; add a password or Passkey first",
            )
        }
        Ok(crate::oauth::providers::repository::UnlinkIdentityOutcome::AuthenticationChanged) => {
            error::unauthorized(
                "password_reauthentication_failed",
                "password reauthentication failed",
            )
        }
        Err(ExternalIdentityUnlinkError::Database(error_value)) => {
            tracing::error!(error = %error_value, "failed to unlink external identity");
            error::internal()
        }
        Err(ExternalIdentityUnlinkError::Missing) => error::not_found(
            "oauth_identity_not_found",
            "linked external identity was not found",
        ),
        Err(ExternalIdentityUnlinkError::LastCredential) => error::conflict(
            "oauth_last_login_credential",
            "cannot unlink the last usable login credential; add a password or Passkey first",
        ),
    }
}
