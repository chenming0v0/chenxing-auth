use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{current_admin_mutation, current_admin_permission},
    domain::AdminPermission,
};
use crate::{
    audit::AuditEvent,
    error,
    settings::{
        EmailPolicySetting, PasskeySetting, REGISTRATION_EMAIL_FROM_KEY, SettingsServiceError,
        SmtpSettingUpdate,
    },
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct UpdateRegistrationEmail {
    pub registration_email_from: Option<Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationEmailSettingResponse {
    pub registration_email_from: Option<String>,
}

pub async fn get_registration_email(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageSettings).await
    {
        return response;
    }
    match state.settings.registration_email_from().await {
        Ok(registration_email_from) => (
            StatusCode::OK,
            Json(RegistrationEmailSettingResponse {
                registration_email_from,
            }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = ?error_value, "failed to load registration email setting");
            error::internal()
        }
    }
}

pub async fn update_registration_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateRegistrationEmail>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(admin_id) => admin_id,
            Err(response) => return response,
        };
    let Some(registration_email_from) = input.registration_email_from else {
        return error::bad_request(
            "invalid_request",
            "registration_email_from must be provided",
        );
    };
    let registration_email_from = match state
        .settings
        .set_registration_email_from(registration_email_from)
        .await
    {
        Ok(value) => value,
        Err(SettingsServiceError::InvalidEmail) => {
            return error::bad_request("invalid_email", "registration sender email is invalid");
        }
        Err(SettingsServiceError::Database(error_value)) => {
            tracing::error!(error = %error_value, "failed to update registration email setting");
            return error::internal();
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update registration email setting");
            return error::internal();
        }
    };
    if record_setting_event(
        &state,
        actor,
        "registration_email_update",
        REGISTRATION_EMAIL_FROM_KEY,
        serde_json::json!({"configured": registration_email_from.is_some()}),
    )
    .await
    .is_err()
    {
        return error::internal();
    }
    (
        StatusCode::OK,
        Json(RegistrationEmailSettingResponse {
            registration_email_from,
        }),
    )
        .into_response()
}

pub async fn get_passkey_setting(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageSettings).await
    {
        return response;
    }
    match state.settings.passkey().await {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load passkey setting");
            error::internal()
        }
    }
}

pub async fn update_passkey_setting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PasskeySetting>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if !input.enabled {
        match state.factors.has_active_passkey_only_accounts().await {
            Ok(true) => {
                tracing::warn!(
                    event = "passkey_setting.disable_blocked",
                    "passkey disable blocked because an active account has no alternative factor"
                );
                return error::conflict(
                    "passkey_disable_blocked",
                    "Passkey cannot be disabled while an active account relies on it as its only factor",
                );
            }
            Ok(false) => {}
            Err(error_value) => {
                tracing::error!(
                    error = %error_value,
                    "failed to check passkey-only accounts before disabling Passkey"
                );
                return error::internal();
            }
        }
    }
    match state.settings.set_passkey(input).await {
        Ok(setting) => {
            if record_setting_event(
                &state,
                actor,
                "passkey_setting_update",
                "passkey",
                serde_json::json!({
                    "enabled": setting.enabled,
                    "rp_id": setting.rp_id,
                    "allow_insecure_origin": setting.allow_insecure_origin,
                    "origin_count": setting.allowed_origins.len(),
                }),
            )
            .await
            .is_err()
            {
                return error::internal();
            }
            (StatusCode::OK, Json(setting)).into_response()
        }
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_passkey_setting", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update passkey setting");
            error::internal()
        }
    }
}

pub async fn get_email_policy_setting(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageSettings).await
    {
        return response;
    }
    match state.settings.email_policy().await {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load email policy setting");
            error::internal()
        }
    }
}

pub async fn update_email_policy_setting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EmailPolicySetting>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    match state.settings.set_email_policy(input).await {
        Ok(setting) => {
            if record_setting_event(
                &state,
                actor,
                "email_policy_update",
                "email_policy",
                serde_json::json!({
                    "whitelist_enabled": setting.whitelist_enabled,
                    "alias_restriction_enabled": setting.alias_restriction_enabled,
                    "domain_count": setting.allowed_domains.len(),
                }),
            )
            .await
            .is_err()
            {
                return error::internal();
            }
            (StatusCode::OK, Json(setting)).into_response()
        }
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_email_policy", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update email policy setting");
            error::internal()
        }
    }
}

pub async fn get_smtp_setting(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageSettings).await
    {
        return response;
    }
    match state.settings.smtp().await {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load smtp setting");
            error::internal()
        }
    }
}

pub async fn update_smtp_setting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SmtpSettingUpdate>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    match state.settings.set_smtp(input).await {
        Ok(setting) => {
            if record_setting_event(
                &state,
                actor,
                "smtp_setting_update",
                "smtp",
                serde_json::json!({
                    "host_configured": !setting.host.is_empty(),
                    "ssl_enabled": setting.ssl_enabled,
                    "force_auth_login": setting.force_auth_login,
                    "password_configured": setting.password_configured,
                }),
            )
            .await
            .is_err()
            {
                return error::internal();
            }
            (StatusCode::OK, Json(setting)).into_response()
        }
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_smtp_setting", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update smtp setting");
            error::internal()
        }
    }
}

async fn record_setting_event(
    state: &AppState,
    actor: super::authorization::AdminActor,
    action: &str,
    resource_id: &str,
    metadata: serde_json::Value,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
            actor.actor_type().to_owned(),
            actor.user_id().map(|id| id.to_string()),
            action.to_owned(),
            "setting".to_owned(),
            Some(resource_id.to_owned()),
            metadata,
        ))
        .await
}
