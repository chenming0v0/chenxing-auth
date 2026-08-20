use axum::{
    Json,
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::AuditEvent,
    error,
    settings::{
        EMAIL_POLICY_KEY, EmailPolicySetting, PasskeySetting, REGISTRATION_EMAIL_FROM_KEY,
        SECURITY_LIMITS_KEY, SESSION_LIFETIME_KEY, SecurityLimitsSetting, SessionLifetimeSetting,
        SettingInspection, SettingsServiceError, SmtpSettingUpdate,
    },
    state::AppState,
};

pub use super::issuer_settings_handlers::{
    IssuerRecordResponse, IssuerSettingResponse, UpdateIssuerSetting, get_issuer_setting,
    update_issuer_setting,
};

pub async fn get_passkey_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_passkey().await {
        Ok(inspection) => respond_setting_inspection("passkey", inspection),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load passkey setting");
            error::internal()
        }
    }
}

pub async fn update_passkey_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<PasskeySetting>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state
        .factors
        .set_passkey_policy_audited(input, &state.audit, move |setting| {
            setting_event(
                actor,
                crate::audit::AuditAction::PasskeySettingUpdate,
                "passkey",
                serde_json::json!({
                    "enabled": setting.enabled,
                    "rp_id": setting.rp_id.clone(),
                    "allow_insecure_origin": setting.allow_insecure_origin,
                    "origin_count": setting.allowed_origins.len(),
                }),
            )
        })
        .await
    {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(crate::auth_factors::service::PasskeyPolicyUpdateError::DisableBlocked) => {
            tracing::warn!(
                event = "passkey_setting.disable_blocked",
                "passkey disable blocked because an active account has no readable alternative factor"
            );
            error::conflict(
                "passkey_disable_blocked",
                "Passkey cannot be disabled while an active account relies on it as its only factor",
            )
        }
        Err(crate::auth_factors::service::PasskeyPolicyUpdateError::Validation(error_value)) => {
            error::bad_request("invalid_passkey_setting", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update passkey setting");
            error::internal()
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailPolicySettingResponse {
    pub whitelist_enabled: bool,
    pub alias_restriction_enabled: bool,
    pub allowed_domains: Vec<String>,
    pub generation: i64,
}

impl EmailPolicySettingResponse {
    fn from_setting(setting: EmailPolicySetting, generation: i64) -> Self {
        Self {
            whitelist_enabled: setting.whitelist_enabled,
            alias_restriction_enabled: setting.alias_restriction_enabled,
            allowed_domains: setting.allowed_domains,
            generation,
        }
    }
}

pub async fn get_email_policy_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_email_policy().await {
        Ok(inspection) => {
            let generation = match crate::settings::repository::get_generation(
                &state.database,
                EMAIL_POLICY_KEY,
            )
            .await
            {
                Ok(generation) => generation,
                Err(error_value) => {
                    tracing::error!(error = %error_value, "failed to load email policy generation");
                    return error::internal();
                }
            };
            let response = respond_setting_inspection(
                "email_policy",
                SettingInspection {
                    value: EmailPolicySettingResponse::from_setting(inspection.value, generation),
                    diagnostic: inspection.diagnostic,
                },
            );
            response
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load email policy setting");
            error::internal()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateEmailPolicySetting {
    #[serde(flatten)]
    setting: EmailPolicySetting,
    expected_generation: i64,
}

pub async fn update_email_policy_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<UpdateEmailPolicySetting>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state
        .settings
        .set_email_policy_audited_if_generation(
            input.setting,
            input.expected_generation,
            &state.audit,
            move |setting| {
                setting_event(
                    actor,
                    crate::audit::AuditAction::EmailPolicyUpdate,
                    "email_policy",
                    serde_json::json!({
                        "whitelist_enabled": setting.whitelist_enabled,
                        "alias_restriction_enabled": setting.alias_restriction_enabled,
                        "domain_count": setting.allowed_domains.len(),
                    }),
                )
            },
        )
        .await
    {
        Ok(setting) => {
            let generation = match crate::settings::repository::get_generation(
                &state.database,
                EMAIL_POLICY_KEY,
            )
            .await
            {
                Ok(generation) => generation,
                Err(error_value) => {
                    tracing::error!(error = %error_value, "failed to load email policy generation");
                    return error::internal();
                }
            };
            (
                StatusCode::OK,
                Json(EmailPolicySettingResponse::from_setting(
                    setting, generation,
                )),
            )
                .into_response()
        }
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_email_policy", error_value.to_string())
        }
        Err(SettingsServiceError::Conflict) => {
            error::conflict("setting_conflict", "setting changed; reload and retry")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update email policy setting");
            error::internal()
        }
    }
}

pub async fn get_smtp_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
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
    admin: AdminWrite,
    ApiJson(input): ApiJson<SmtpSettingUpdate>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state
        .settings
        .set_smtp_audited(input, &state.audit, move |(setting, password_action)| {
            setting_event(
                actor,
                crate::audit::AuditAction::SmtpSettingUpdate,
                "smtp",
                serde_json::json!({
                    "host_configured": !setting.host.is_empty(),
                    "ssl_enabled": setting.ssl_enabled,
                    "force_auth_login": setting.force_auth_login,
                    "password_configured": setting.password_configured,
                    "password_action": password_action,
                }),
            )
        })
        .await
    {
        Ok((setting, _)) => (StatusCode::OK, Json(setting)).into_response(),
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_smtp_setting", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update smtp setting");
            error::internal()
        }
    }
}

pub async fn get_session_lifetime_setting(
    State(state): State<AppState>,
    admin: AdminRead,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_session_lifetime().await {
        Ok(inspection) => respond_setting_inspection("session_lifetime", inspection),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load session lifetime setting");
            error::internal()
        }
    }
}

pub async fn update_session_lifetime_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<SessionLifetimeSetting>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state
        .settings
        .set_session_lifetime_audited(input, &state.audit, move |setting| {
            setting_event(
                actor,
                crate::audit::AuditAction::SessionLifetimeUpdate,
                SESSION_LIFETIME_KEY,
                serde_json::json!({"session_ttl_seconds": setting.session_ttl_seconds}),
            )
        })
        .await
    {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_session_lifetime", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update session lifetime setting");
            error::internal()
        }
    }
}

pub async fn get_security_limits_setting(
    State(state): State<AppState>,
    admin: AdminRead,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_security_limits().await {
        Ok(inspection) => respond_setting_inspection("security_limits", inspection),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load security limits setting");
            error::internal()
        }
    }
}

pub async fn update_security_limits_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<SecurityLimitsSetting>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state
        .settings
        .set_security_limits_audited(input, &state.audit, move |setting| {
            setting_event(
                actor,
                crate::audit::AuditAction::SecurityLimitsUpdate,
                SECURITY_LIMITS_KEY,
                serde_json::json!({
                    "unauthenticated_source_qps": setting.unauthenticated_source_qps,
                    "authorization_code_ttl_seconds": setting.authorization_code_ttl_seconds,
                    "pending_request_ttl_seconds": setting.pending_request_ttl_seconds,
                    "max_pending_requests_per_client": setting.max_pending_requests_per_client,
                    "max_pending_requests_global": setting.max_pending_requests_global,
                    "auth_failure_window_seconds": setting.auth_failure_window_seconds,
                    "account_failure_limit": setting.account_failure_limit,
                    "ip_failure_limit": setting.ip_failure_limit,
                    "totp_ticket_failure_limit": setting.totp_ticket_failure_limit,
                    "external_login_state_ttl_seconds": setting.external_login_state_ttl_seconds,
                    "external_login_state_rate_window_seconds": setting.external_login_state_rate_window_seconds,
                    "external_login_state_rate_limit": setting.external_login_state_rate_limit,
                    "external_login_state_max_pending": setting.external_login_state_max_pending,
                }),
            )
        })
        .await
    {
        Ok(setting) => {
            (StatusCode::OK, Json(setting)).into_response()
        }
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_security_limits", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update security limits setting");
            error::internal()
        }
    }
}

/// 管理读取把可修复诊断放在这个响应头里，JSON body 保持设置对象本身。
/// 取值只有 `invalid` / `corrupt`，不含配置原文。
pub(crate) const SETTING_DIAGNOSTIC_HEADER: HeaderName =
    HeaderName::from_static("x-chenxing-setting-diagnostic");

pub(crate) fn respond_setting_inspection<T: Serialize>(
    setting_key: &'static str,
    inspection: SettingInspection<T>,
) -> Response {
    let mut response = (StatusCode::OK, Json(inspection.value)).into_response();
    if let Some(diagnostic) = &inspection.diagnostic {
        tracing::warn!(
            event = "settings.admin_read_needs_repair",
            setting_key,
            diagnostic = diagnostic.as_str(),
            "stored setting is readable for repair but must not be used on the security hot path"
        );
        response.headers_mut().insert(
            SETTING_DIAGNOSTIC_HEADER,
            HeaderValue::from_static(diagnostic.as_str()),
        );
    }
    response
}

#[cfg(test)]
#[path = "settings_handlers_tests.rs"]
mod tests;

pub(crate) fn setting_event(
    actor: super::authorization::AdminActor,
    action: crate::audit::AuditAction,
    resource_id: &str,
    metadata: serde_json::Value,
) -> AuditEvent {
    AuditEvent::new(
        actor.actor_type().to_owned(),
        actor.user_id().map(|id| id.to_string()),
        action,
        "setting".to_owned(),
        Some(resource_id.to_owned()),
        metadata,
    )
}
