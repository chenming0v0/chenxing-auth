//! 公开注册开关的管理端点（`/api/v1/admin/settings/registration`）。
//!
//! 与其余管理设置同构：读走 [`AdminRead`]，写走 [`AdminWrite`]（CSRF 三绑定在
//! `authorize()` 内无条件校验），权限均为 [`AdminPermission::ManageSettings`]，
//! 写入与审计同事务。单独成文件是因为 `settings_handlers.rs` 已接近行数上限。

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::{domain::AdminPermission, settings_handlers::setting_event};
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    error,
    settings::{REGISTRATION_SETTING_KEY, RegistrationSetting, SettingsServiceError},
    state::AppState,
};

pub async fn get_registration_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.settings.inspect_registration().await {
        Ok(inspection) => super::settings_handlers::respond_setting_inspection(
            REGISTRATION_SETTING_KEY,
            inspection,
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load registration setting");
            error::internal()
        }
    }
}

pub async fn update_registration_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<RegistrationSetting>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    // 打开公开注册要求 Issuer 就绪：注册出来的账号要能走完整认证/授权流程，
    // Issuer 未配置的实例即使开关打开，`POST /api/v1/users` 也会被 issuer 闸门
    // 以 503 关闭。在写入时刻拦住，避免留下「开关是开的、注册却全部 503」的
    // 分裂状态；这也与匿名 `registration-status` 的有效值语义（开关 AND Issuer
    // 就绪）保持一致。
    if input.enabled && !state.issuer.is_ready() {
        return error::issuer_not_configured();
    }
    match state
        .settings
        .set_registration_audited(input, &state.audit, move |setting| {
            setting_event(
                actor,
                crate::audit::AuditAction::RegistrationSettingUpdate,
                REGISTRATION_SETTING_KEY,
                serde_json::json!({
                    "enabled": setting.enabled,
                    "email_verification_required": setting.email_verification_required,
                    "invitation_code_required": setting.invitation_code_required,
                }),
            )
        })
        .await
    {
        Ok(setting) => (StatusCode::OK, Json(setting)).into_response(),
        Err(SettingsServiceError::Validation(error_value)) => {
            error::bad_request("invalid_registration_setting", error_value.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update registration setting");
            error::internal()
        }
    }
}
