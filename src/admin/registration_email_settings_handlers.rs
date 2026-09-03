use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{domain::AdminPermission, settings_handlers::setting_event};
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    error,
    settings::{REGISTRATION_EMAIL_FROM_KEY, SettingsServiceError},
    state::AppState,
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
        .authorize(&state, AdminPermission::ManageSystemSettings)
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
    let authorization = match crate::admin::authorization::authorize_admin_write(
        &state,
        &admin,
        AdminPermission::ManageSystemSettings,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    let Some(registration_email_from) = input.registration_email_from else {
        return error::bad_request(
            "invalid_request",
            "registration_email_from must be provided",
        );
    };
    let registration_email_from = match state
        .settings
        .set_registration_email_from_audited(
            registration_email_from,
            &state.audit,
            authorization.credential(),
            move |value| {
                setting_event(
                    actor,
                    crate::audit::AuditAction::RegistrationEmailUpdate,
                    REGISTRATION_EMAIL_FROM_KEY,
                    serde_json::json!({"configured": value.is_some()}),
                )
            },
        )
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
