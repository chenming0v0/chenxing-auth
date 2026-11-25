use axum::response::Response;

use crate::{
    error,
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        token::{AccessTokenClaims, decode_userinfo_token},
    },
    resource_services::{ProviderScope, ServiceError, types::BindingRow},
    state::AppState,
    users::domain::UserStatus,
};

use super::{denied, record_denied, support::NOT_LINKED_MESSAGE, ticket::AppKind, unavailable};

pub(super) async fn query_error(
    state: &AppState,
    binding: &BindingRow,
    sub: &str,
    provider: &ProviderScope,
    error_value: ServiceError,
) -> Response {
    match error_value {
        ServiceError::BindingTombstoned => {
            let disabled = binding.snapshot_json["status"] == "disabled";
            if disabled {
                record_denied(state, Some(sub), "account_disabled", Some(&provider.slug)).await;
                error::forbidden("account_disabled", "the linked account is disabled")
            } else {
                error::forbidden("account_not_linked", NOT_LINKED_MESSAGE)
            }
        }
        ServiceError::BindingNotFound => error::forbidden("account_not_linked", NOT_LINKED_MESSAGE),
        ServiceError::ReauthorizationRequired | ServiceError::CredentialInvalid => {
            record_denied(
                state,
                Some(sub),
                "reauthorization_required",
                Some(&provider.slug),
            )
            .await;
            error::forbidden(
                "reauthorization_required",
                "the linked account requires reauthorization",
            )
        }
        ServiceError::UserDisabled => {
            record_denied(state, Some(sub), "account_disabled", Some(&provider.slug)).await;
            error::forbidden("account_disabled", "the account is disabled")
        }
        ServiceError::RateLimited { .. } => {
            record_denied(state, Some(sub), "rate_limited", Some(&provider.slug)).await;
            error::too_many_requests("rate_limited", "the provider rate limited the request")
        }
        _ => unavailable(state, Some(sub), Some(&provider.slug)).await,
    }
}

/// 出网期间本地授权可能变化；签票前重新确认同一身份、应用、同意和关联。
pub(super) async fn revalidate(
    state: &AppState,
    claims: &AccessTokenClaims,
    token: &str,
    consent_version: i64,
    provider: &ProviderScope,
    binding: &BindingRow,
    app: AppKind,
) -> Result<BindingRow, Response> {
    let sub = claims.sub.as_str();
    let slug = Some(provider.slug.as_str());
    if decode_userinfo_token(&state.keys, &claims.iss, token).is_err()
        || usize::try_from(state.clock.now().unix_timestamp()).is_ok_and(|now| claims.exp <= now)
    {
        return Err(denied(state, Some(sub), slug).await);
    }
    match state.issuer.current() {
        Some(current) if current.issuer().as_str() == claims.iss => {}
        _ => return Err(denied(state, Some(sub), slug).await),
    }
    match state.revocations.is_revoked(token).await {
        Ok(false) => {}
        Ok(true) => return Err(denied(state, Some(sub), slug).await),
        Err(_) => return Err(unavailable(state, Some(sub), slug).await),
    }
    let presented = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    match effective_grant_scopes(state, sub, &claims.aud, &presented).await {
        Ok(grant)
            if grant.consent_version == consent_version
                && grant.scopes.iter().any(|scope| scope == &provider.scope) => {}
        Ok(_) | Err(GrantGateError::Denied(_)) => return Err(denied(state, Some(sub), slug).await),
        Err(GrantGateError::Unavailable(_)) => {
            return Err(unavailable(state, Some(sub), slug).await);
        }
    }
    match state.clients.find_registered(&claims.aud).await {
        Ok(Some(client))
            if client
                .android_package
                .as_deref()
                .and_then(AppKind::from_package)
                == Some(app) => {}
        Ok(_) => {
            return Err(error::forbidden(
                "app_not_allowed",
                "the OAuth client is not allowed for this app",
            ));
        }
        Err(_) => return Err(unavailable(state, Some(sub), slug).await),
    }
    match state.users.find_profile(binding.user_id).await {
        Ok(Some(profile)) if UserStatus::parse(&profile.status) == Some(UserStatus::Active) => {}
        Ok(_) => {
            return Err(error::forbidden(
                "account_disabled",
                "the account is disabled",
            ));
        }
        Err(_) => return Err(unavailable(state, Some(sub), slug).await),
    }
    let fresh = match state
        .resource_services
        .live_binding(provider.provider_id, binding.user_id)
        .await
    {
        Ok(Some(row)) if row.id == binding.id && row.uid == binding.uid => row,
        Ok(_) => return Err(error::forbidden("account_not_linked", NOT_LINKED_MESSAGE)),
        Err(_) => return Err(unavailable(state, Some(sub), slug).await),
    };
    Ok(fresh)
}
