use crate::{error, state::AppState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Public-facing view of an external identity provider: only what the login page
/// needs to render a button. Deliberately omits endpoints, client_id and claims.
#[derive(Debug, serde::Serialize)]
pub struct PublicProvider {
    pub slug: String,
    pub name: String,
}

/// Lists active external OAuth providers for the SPA login page. No auth required —
/// the same list was previously baked into the server-rendered login HTML.
pub async fn list_public_providers(State(state): State<AppState>) -> Response {
    match state.external_oauth.list().await {
        Ok(providers) => {
            let active: Vec<PublicProvider> = providers
                .into_iter()
                .filter(|provider| provider.status == "active" && provider.claim_mapping().is_ok())
                .map(|provider| PublicProvider {
                    slug: provider.slug,
                    name: provider.name,
                })
                .collect();
            (StatusCode::OK, axum::Json(active)).into_response()
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list public external providers");
            error::internal()
        }
    }
}
