use axum::response::Response;
use serde::Serialize;
use std::fmt;

use crate::{
    clients::service::RegisteredClientSecret, oauth::quota::QuotaSnapshot, state::AppState,
};

#[derive(Debug, Serialize)]
pub(super) struct OwnedClientResponse {
    pub(super) id: i64,
    pub(super) client_id: String,
    pub(super) client_name: String,
    pub(super) redirect_uris: Vec<String>,
    pub(super) scopes: Vec<String>,
    pub(super) status: String,
    pub(super) quota: QuotaSnapshot,
}

#[derive(Serialize)]
pub(super) struct RegisteredOwnedClientResponse {
    #[serde(flatten)]
    pub(super) client: OwnedClientResponse,
    /// Client 认证方式；`none` 表示公开客户端，响应不含 client_secret。
    pub(super) auth_method: &'static str,
    /// 公开客户端（SPA / 移动端）不签发 secret，此时该字段整体省略（Issue #66）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) client_secret: Option<String>,
}

impl fmt::Debug for RegisteredOwnedClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredOwnedClientResponse")
            .field("client", &self.client)
            .field("auth_method", &self.auth_method)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub(super) async fn owned_registered_response(
    state: &AppState,
    client: RegisteredClientSecret,
    quota_limits: Option<crate::plans::domain::AuthQuotaLimits>,
) -> Result<RegisteredOwnedClientResponse, Response> {
    // Quota usage is enrichment, not part of the one-time credential commit.
    // Redis can be unavailable immediately after the client row commits; do
    // not turn that into a 500 which hides the only returned secret (#50).
    let quota = match state
        .oauth_quotas
        .snapshot_at(&client.client_id, quota_limits, state.clock.now())
        .await
    {
        Ok(quota) => quota,
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                client_id = %client.client_id,
                "failed to load quota snapshot after client creation"
            );
            QuotaSnapshot {
                daily_limit: quota_limits.map(|limits| limits.daily_auth_limit),
                daily_used: 0,
                monthly_limit: quota_limits.and_then(|limits| limits.monthly_auth_limit),
                monthly_used: 0,
            }
        }
    };
    Ok(RegisteredOwnedClientResponse {
        client: OwnedClientResponse {
            id: client.id,
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            status: "active".to_owned(),
            quota,
        },
        auth_method: client.auth_method.as_str(),
        client_secret: client.client_secret,
    })
}
