use std::sync::Arc;

use axum::{
    extract::{Request as AxumRequest, State},
    middleware::Next,
    response::Response,
};

use crate::{settings::IssuerRuntimeState, state::AppState};

pub(super) async fn require_issuer(
    State(state): State<AppState>,
    mut request: AxumRequest,
    next: Next,
) -> Response {
    let runtime = match converge_awaiting(&state).await {
        Ok(runtime) => runtime,
        Err(()) => return unavailable_response(request.uri().path(), false),
    };
    let Some(snapshot) = runtime.loaded() else {
        if matches!(runtime.as_ref(), IssuerRuntimeState::AwaitingIssuer)
            && !requires_configured_issuer(request.uri().path())
        {
            return next.run(request).await;
        }
        return unavailable_response(
            request.uri().path(),
            matches!(runtime.as_ref(), IssuerRuntimeState::AwaitingIssuer),
        );
    };
    request.extensions_mut().insert(snapshot.clone());
    let mut response = next.run(request).await;
    response.extensions_mut().insert(snapshot);
    response
}

async fn converge_awaiting(state: &AppState) -> Result<Arc<IssuerRuntimeState>, ()> {
    let runtime = state.issuer.state();
    if !matches!(runtime.as_ref(), IssuerRuntimeState::AwaitingIssuer) {
        return Ok(runtime);
    }

    let record = match crate::settings::issuer::load_raw(&state.database).await {
        Ok(record) => record,
        Err(_) => {
            let current = state.issuer.state();
            if !Arc::ptr_eq(&runtime, &current) {
                return Ok(current);
            }
            tracing::warn!(
                event = "issuer.gate_reload_failed",
                "failed to refresh issuer state before routing the request"
            );
            return Err(());
        }
    };

    if state
        .issuer
        .apply_raw_if_unchanged(&runtime, record.as_ref())
        .is_err()
    {
        tracing::warn!(
            event = "issuer.gate_runtime_invalid",
            generation = record.as_ref().map(|record| record.generation),
            "persisted issuer could not be applied; issuer-dependent routes remain closed"
        );
    }
    Ok(state.issuer.state())
}

fn unavailable_response(path: &str, issuer_absent: bool) -> Response {
    if crate::error::is_oauth_protocol_path(path) {
        return crate::error::oauth_temporarily_unavailable();
    }
    if issuer_absent {
        crate::error::issuer_not_configured()
    } else {
        crate::error::issuer_runtime_invalid()
    }
}

fn requires_configured_issuer(path: &str) -> bool {
    crate::error::is_oauth_protocol_path(path)
        || matches!(
            path,
            "/.well-known/openid-configuration"
                | "/.well-known/jwks.json"
                | "/api/v1/auth/external-providers"
                | "/api/v1/auth/totp/setup"
                | "/api/v1/auth/security/totp/enrollment/start"
        )
        || exact_dynamic_route(path, &["api", "v1", "oauth", "authorize", "requests"], None)
        || exact_dynamic_route(
            path,
            &["api", "v1", "oauth", "authorize", "requests"],
            Some("bind"),
        )
        || path == "/api/v1/admin/oauth/providers"
        || exact_dynamic_route(path, &["api", "v1", "admin", "oauth", "providers"], None)
        || exact_dynamic_route(
            path,
            &["api", "v1", "admin", "oauth", "providers"],
            Some("disable"),
        )
        || exact_dynamic_route(
            path,
            &["api", "v1", "admin", "oauth", "providers"],
            Some("enable"),
        )
        || exact_dynamic_route(path, &["auth", "external"], None)
        || exact_dynamic_route(path, &["auth", "external"], Some("callback"))
}

fn exact_dynamic_route(path: &str, prefix: &[&str], suffix: Option<&str>) -> bool {
    let segments: Vec<_> = path.split('/').skip(1).collect();
    let expected_len = prefix.len() + 1 + usize::from(suffix.is_some());
    if segments.len() != expected_len || segments[..prefix.len()] != *prefix {
        return false;
    }
    if segments[prefix.len()].is_empty() {
        return false;
    }
    suffix.is_none_or(|suffix| segments.last() == Some(&suffix))
}

#[cfg(test)]
mod tests {
    use super::requires_configured_issuer;

    #[test]
    fn gate_only_covers_protocol_and_external_login_routes() {
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/revoke",
            "/oauth/userinfo",
            "/api/v1/auth/totp/setup",
            "/api/v1/auth/security/totp/enrollment/start",
            "/api/v1/oauth/authorize/requests/request-id",
            "/api/v1/oauth/authorize/requests/request-id/bind",
            "/api/v1/admin/oauth/providers",
            "/api/v1/admin/oauth/providers/example",
            "/api/v1/admin/oauth/providers/example/disable",
            "/api/v1/admin/oauth/providers/example/enable",
            "/api/v1/auth/external-providers",
            "/auth/external/example",
            "/auth/external/example/callback",
        ] {
            assert!(requires_configured_issuer(path), "path={path}");
        }

        for path in [
            "/api/v1/auth/login",
            "/api/v1/auth/me",
            "/api/v1/admin/auth/me",
            "/api/v1/admin/settings/issuer",
            "/api/v1/admin/users",
            "/api/v1/users",
            "/api/v1/oauth/authorize/requests/",
            "/api/v1/oauth/authorize/requests/request-id/bind/extra",
            "/api/v1/admin/oauth/providers/example/delete",
            "/api/v1/admin/oauth/providers/example/disable/extra",
            "/auth/external/",
            "/auth/external/example/callback/extra",
        ] {
            assert!(!requires_configured_issuer(path), "path={path}");
        }
    }
}
