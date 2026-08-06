use axum::response::Response;

use super::client_auth::ClientCredentials;
use crate::{audit::AuditEvent, error, state::AppState};

pub(crate) async fn enforce_source_qps(state: &AppState, source_ip: &str) -> Option<Response> {
    // #121：QPS 阈值从配置读取，不再硬编码。默认值30保持向后兼容。
    let qps_limit = state.config.security_limits.unauthenticated_source_qps;
    match state.qps.allow_source(source_ip, qps_limit).await {
        Ok(true) => None,
        Ok(false) => {
            if let Err(error_value) = record_token_event(
                state,
                None,
                "rate_limit_triggered",
                None,
                "oauth_source_qps",
            )
            .await
            {
                tracing::warn!(
                    error = %error_value,
                    "failed to record OAuth source rate limit audit event"
                );
            }
            Some(error::oauth_too_many_requests(
                "temporarily_unavailable",
                "request rate limit exceeded",
            ))
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "source rate limit check failed");
            Some(error::oauth_temporarily_unavailable())
        }
    }
}

pub(crate) async fn enforce_qps(state: &AppState, client_id: &str) -> Option<Response> {
    let client = match state.clients.find_registered(client_id).await {
        Ok(Some(client)) => client,
        // Unknown clients are rejected later by credential checks; there is no plan to enforce yet.
        Ok(None) => return None,
        Err(error_value) => {
            // Fail closed: a DB blip must not disable QPS for an otherwise valid client.
            tracing::error!(error = %error_value, "failed to load OAuth client for QPS limit");
            return Some(error::oauth_temporarily_unavailable());
        }
    };
    let Some(owner_user_id) = client.owner_user_id else {
        // Admin-created clients without an owner are not bound to user plan QPS.
        return None;
    };
    let effective = match state.plans.effective_plan_for_user(owner_user_id).await {
        Ok(effective) => effective,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load plan for QPS limit");
            return Some(error::oauth_temporarily_unavailable());
        }
    };
    let max_qps = effective.plan.max_qps?;
    match state.qps.allow(client_id, max_qps.max(1) as u32).await {
        Ok(true) => None,
        Ok(false) => {
            // Rate-limit denials should not depend on audit durability; log and still 429.
            if let Err(error_value) = record_token_event(
                state,
                None,
                "rate_limit_triggered",
                Some(client_id),
                "oauth_qps",
            )
            .await
            {
                tracing::warn!(
                    error = %error_value,
                    "failed to record OAuth QPS rate limit audit event"
                );
            }
            Some(error::oauth_too_many_requests(
                "temporarily_unavailable",
                "request rate limit exceeded",
            ))
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "QPS rate limit check failed");
            Some(error::oauth_temporarily_unavailable())
        }
    }
}

pub(crate) async fn verify_client_credentials(
    state: &AppState,
    credentials: &ClientCredentials,
) -> Option<Response> {
    match state
        .clients
        .verify_credentials(
            &credentials.client_id,
            credentials.auth_method,
            credentials.client_secret.as_deref(),
        )
        .await
    {
        Ok(true) => None,
        Ok(false) => Some(error::oauth_invalid_client()),
        Err(client_error) => {
            tracing::error!(error = %client_error, "failed to verify OAuth client credentials");
            Some(error::oauth_temporarily_unavailable())
        }
    }
}

pub(crate) async fn record_token_event(
    state: &AppState,
    actor_id: Option<&str>,
    action: &str,
    client_id: Option<&str>,
    reason: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "oauth_client".to_owned()
            },
            actor_id.map(str::to_owned),
            action.to_owned(),
            "oauth_token".to_owned(),
            client_id.map(str::to_owned),
            serde_json::json!({"reason": reason}),
        ))
        .await
}
