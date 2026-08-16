use axum::{
    Json,
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::AuditEvent,
    error,
    settings::{
        EmailPolicySetting, PasskeySetting, REGISTRATION_EMAIL_FROM_KEY, SECURITY_LIMITS_KEY,
        SecurityLimitsSetting, SettingInspection, SettingsServiceError, SmtpSettingUpdate,
    },
    state::AppState,
};

pub use super::issuer_settings_handlers::{
    IssuerRecordResponse, IssuerSettingResponse, UpdateIssuerSetting, get_issuer_setting,
    update_issuer_setting,
};

/// 注册发件人的三态更新：缺失 = 非法请求，`null` = 清除，字符串 = 设置。
///
/// serde 对外层 `Option` 的特例化会把 JSON `null` 直接吞成 `None`（等同缺失），
/// 内层 `Option` 永远收不到 `null`，`Some(None)` 这一「清除」态无从产生。
/// 因此必须用 `deserialize_with` 把 null 转发给内层 Option：
///
/// - 字段缺失：`#[serde(default)]` 生效，`None` → handler 返回 `invalid_request`。
/// - `null`：helper 得到 `Some(None)` → handler 清除。
/// - `"a@b.c"`：helper 得到 `Some(Some("a@b.c"))` → handler 设置。
#[derive(Debug, Deserialize)]
pub struct UpdateRegistrationEmail {
    #[serde(default, deserialize_with = "deserialize_tri_state")]
    pub registration_email_from: Option<Option<String>>,
}

/// 把 JSON `null` 转成 `Some(None)`，其余值正常解析。
fn deserialize_tri_state<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Serialize)]
pub struct RegistrationEmailSettingResponse {
    pub registration_email_from: Option<String>,
}

pub async fn get_registration_email(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
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
    admin: AdminWrite,
    ApiJson(input): ApiJson<UpdateRegistrationEmail>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
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
        .set_registration_email_from_audited(registration_email_from, &state.audit, move |value| {
            setting_event(
                actor,
                crate::audit::AuditAction::RegistrationEmailUpdate,
                REGISTRATION_EMAIL_FROM_KEY,
                serde_json::json!({"configured": value.is_some()}),
            )
        })
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
    (
        StatusCode::OK,
        Json(RegistrationEmailSettingResponse {
            registration_email_from,
        }),
    )
        .into_response()
}

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

pub async fn get_email_policy_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_email_policy().await {
        Ok(inspection) => respond_setting_inspection("email_policy", inspection),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load email policy setting");
            error::internal()
        }
    }
}

pub async fn update_email_policy_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<EmailPolicySetting>,
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
        .set_email_policy_audited(input, &state.audit, move |setting| {
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
        })
        .await
    {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_email_policy", error_value.to_string())
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

fn respond_setting_inspection<T: Serialize>(
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

fn setting_event(
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
