use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::Serialize;
use tower_http::trace::TraceLayer;

use crate::{
    admin::auth_handlers::{bootstrap_admin, create_admin, login_admin, logout_admin},
    admin::handlers::{
        create_client, disable_client, enable_client, list_clients, rotate_secret, update_client,
    },
    admin::key_handlers::rotate_signing_key,
    admin::management_handlers::{list_admins, list_audit, list_users, set_user_status},
    admin::web_handlers::{dashboard, login_page, login_submit, protected_placeholder},
    oauth::OpenIdConfiguration,
    oauth::handlers::{authorize, token},
    oauth::revocation_handler::revoke,
    oauth::userinfo::userinfo,
    state::AppState,
    users::handlers::{login_user, register_user, revoke_session},
    web::handlers::{consent_get, consent_post, login_get, login_post},
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(authorize))
        .route(
            "/oauth/authorize/consent",
            get(consent_get).post(consent_post),
        )
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/userinfo", get(userinfo))
        .route("/api/v1/users", post(register_user))
        .route("/api/v1/auth/login", post(login_user))
        .route("/api/v1/admin/bootstrap", post(bootstrap_admin))
        .route("/api/v1/admin/admins", get(list_admins).post(create_admin))
        .route("/api/v1/admin/auth/login", post(login_admin))
        .route(
            "/api/v1/admin/auth/logout",
            axum::routing::delete(logout_admin),
        )
        .route("/api/v1/admin/users", get(list_users))
        .route(
            "/api/v1/admin/users/{user_id}/{status}",
            post(set_user_status),
        )
        .route("/api/v1/admin/audit", get(list_audit))
        .route("/admin", get(dashboard))
        .route("/admin/login", get(login_page).post(login_submit))
        .route("/admin/users", get(protected_placeholder))
        .route("/admin/clients", get(protected_placeholder))
        .route("/admin/audit", get(protected_placeholder))
        .route("/auth/login", get(login_get).post(login_post))
        .route(
            "/api/v1/auth/session",
            axum::routing::delete(revoke_session),
        )
        .route(
            "/api/v1/admin/clients",
            axum::routing::get(list_clients).post(create_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}",
            axum::routing::put(update_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/disable",
            axum::routing::post(disable_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/enable",
            axum::routing::post(enable_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/rotate-secret",
            axum::routing::post(rotate_secret),
        )
        .route(
            "/api/v1/admin/keys/rotate",
            axum::routing::post(rotate_signing_key),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: crate::SERVICE_NAME,
    })
}

async fn openid_configuration(State(state): State<AppState>) -> Json<OpenIdConfiguration> {
    Json(OpenIdConfiguration::for_issuer(&state.config.issuer_url))
}

async fn jwks(State(state): State<AppState>) -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(state.keys.jwks())
}
