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
use crate::{audit::AuditEvent, error, settings::SettingsServiceError, state::AppState};

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
    };
    state
        .audit
        .record(AuditEvent::new(
            actor.actor_type().to_owned(),
            actor.user_id().map(|id| id.to_string()),
            "registration_email_update".to_owned(),
            "setting".to_owned(),
            Some(crate::settings::REGISTRATION_EMAIL_FROM_KEY.to_owned()),
            serde_json::json!({"configured": registration_email_from.is_some()}),
        ))
        .await;
    (
        StatusCode::OK,
        Json(RegistrationEmailSettingResponse {
            registration_email_from,
        }),
    )
        .into_response()
}
