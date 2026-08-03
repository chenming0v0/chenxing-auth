use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, Method, StatusCode,
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, ORIGIN, VARY},
    },
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

use crate::{
    admin::auth_handlers::{bootstrap_admin, bootstrap_status, create_admin},
    admin::handlers::{
        create_client, disable_client, enable_client, list_clients, rotate_secret, update_client,
    },
    admin::key_handlers::rotate_signing_key,
    admin::management_handlers::{
        list_admins, list_audit, list_users, set_user_role, set_user_status,
    },
    admin::plan_handlers::{
        archive_plan, assign_plan, create_plan, list_plans, restore_plan, update_plan,
    },
    admin::provider_handlers::{
        create_provider, disable_provider, enable_provider, list_providers, update_provider,
    },
    admin::provider_web_handlers::oauth_settings,
    admin::settings_handlers::{
        get_email_policy_setting, get_passkey_setting, get_registration_email, get_smtp_setting,
        update_email_policy_setting, update_passkey_setting, update_registration_email,
        update_smtp_setting,
    },
    admin::ui_handlers::{admin_me, admin_overview, query_audit, query_clients, query_users},
    admin::web_handlers::{
        audit_page, clients_page, dashboard, login_page, login_submit, users_page,
    },
    auth_factors::handlers::{
        confirm_totp_setup, finish_passkey_authentication, finish_passkey_registration, login_totp,
        start_passkey_authentication, start_passkey_registration, start_totp_setup,
    },
    oauth::OpenIdConfiguration,
    oauth::handlers::{authorize, token},
    oauth::providers::handlers::{external_callback, list_public_providers, start_external_login},
    oauth::revocation_handler::revoke,
    oauth::ui_handlers::{
        bind_authorization_request, decide_authorization_request, inspect_authorization_request,
    },
    oauth::userinfo::userinfo,
    state::AppState,
    users::entitlements_handlers::current_entitlements,
    users::handlers::{login_user, register_user, revoke_session},
    users::oauth_client_handlers::{
        create_owned_client, disable_owned_client, enable_owned_client, list_authorized_apps,
        list_owned_clients, revoke_authorized_app, rotate_owned_client_secret, update_owned_client,
    },
    users::ui_handlers::{
        auth_status, change_current_user_password, current_user_profile, list_user_sessions,
        revoke_user_session, update_current_user_profile,
    },
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
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/userinfo", get(userinfo))
        .route(
            "/api/v1/oauth/authorize/requests/{request_id}",
            get(inspect_authorization_request).post(decide_authorization_request),
        )
        .route(
            "/api/v1/oauth/authorize/requests/{request_id}/bind",
            post(bind_authorization_request),
        )
        .route("/api/v1/users", post(register_user))
        .route("/api/v1/auth/login", post(login_user))
        .route("/api/v1/auth/totp/setup", post(start_totp_setup))
        .route("/api/v1/auth/totp/setup/confirm", post(confirm_totp_setup))
        .route("/api/v1/auth/totp/login", post(login_totp))
        .route(
            "/api/v1/auth/passkeys/register/start",
            post(start_passkey_registration),
        )
        .route(
            "/api/v1/auth/passkeys/register/finish",
            post(finish_passkey_registration),
        )
        .route(
            "/api/v1/auth/passkeys/authentication/start",
            post(start_passkey_authentication),
        )
        .route(
            "/api/v1/auth/passkeys/authentication/finish",
            post(finish_passkey_authentication),
        )
        .route("/api/v1/auth/status", get(auth_status))
        .route(
            "/api/v1/auth/me",
            get(current_user_profile).patch(update_current_user_profile),
        )
        .route("/api/v1/auth/password", post(change_current_user_password))
        .route("/api/v1/auth/entitlements", get(current_entitlements))
        .route("/api/v1/auth/sessions", get(list_user_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            axum::routing::delete(revoke_user_session),
        )
        .route("/api/v1/admin/bootstrap/status", get(bootstrap_status))
        .route("/api/v1/admin/bootstrap", post(bootstrap_admin))
        .route("/api/v1/admin/admins", get(list_admins).post(create_admin))
        .route("/api/v1/admin/auth/me", get(admin_me))
        .route("/api/v1/admin/users", get(list_users))
        .route(
            "/api/v1/admin/users/{user_id}/{status}",
            post(set_user_status),
        )
        .route("/api/v1/admin/users/{user_id}/role", post(set_user_role))
        .route("/api/v1/admin/users/{user_id}/plan", post(assign_plan))
        .route("/api/v1/admin/plans", get(list_plans).post(create_plan))
        .route("/api/v1/admin/plans/{id}", axum::routing::put(update_plan))
        .route("/api/v1/admin/plans/{id}/archive", post(archive_plan))
        .route("/api/v1/admin/plans/{id}/restore", post(restore_plan))
        .route("/api/v1/admin/audit", get(list_audit))
        .route("/api/v1/admin/overview", get(admin_overview))
        .route("/api/v1/admin/users/query", get(query_users))
        .route("/api/v1/admin/clients/query", get(query_clients))
        .route("/api/v1/admin/audit/query", get(query_audit))
        .route(
            "/api/v1/admin/settings/registration-email",
            get(get_registration_email).put(update_registration_email),
        )
        .route(
            "/api/v1/admin/settings/passkey",
            get(get_passkey_setting).put(update_passkey_setting),
        )
        .route(
            "/api/v1/admin/settings/email-policy",
            get(get_email_policy_setting).put(update_email_policy_setting),
        )
        .route(
            "/api/v1/admin/settings/smtp",
            get(get_smtp_setting).put(update_smtp_setting),
        )
        .route(
            "/api/v1/admin/oauth/providers",
            get(list_providers).post(create_provider),
        )
        .route(
            "/api/v1/admin/oauth/providers/{slug}",
            axum::routing::put(update_provider),
        )
        .route(
            "/api/v1/admin/oauth/providers/{slug}/disable",
            post(disable_provider),
        )
        .route(
            "/api/v1/admin/oauth/providers/{slug}/enable",
            post(enable_provider),
        )
        .route("/admin", get(dashboard))
        .route("/admin/login", get(login_page).post(login_submit))
        .route("/admin/users", get(users_page))
        .route("/admin/clients", get(clients_page))
        .route("/admin/audit", get(audit_page))
        .route("/admin/settings/oauth", get(oauth_settings))
        .route(
            "/api/v1/auth/external-providers",
            get(list_public_providers),
        )
        .route("/auth/external/{slug}", get(start_external_login))
        .route("/auth/external/{slug}/callback", get(external_callback))
        .route(
            "/api/v1/auth/session",
            axum::routing::delete(revoke_session),
        )
        .route(
            "/api/v1/auth/oauth-clients",
            axum::routing::get(list_owned_clients).post(create_owned_client),
        )
        .route("/api/v1/auth/authorized-apps", get(list_authorized_apps))
        .route(
            "/api/v1/auth/authorized-apps/{client_id}",
            delete(revoke_authorized_app),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}",
            axum::routing::put(update_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/disable",
            axum::routing::post(disable_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/enable",
            axum::routing::post(enable_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/rotate-secret",
            axum::routing::post(rotate_owned_client_secret),
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
        .fallback(any(web_app))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub(crate) fn source_ip(peer: Option<SocketAddr>) -> Option<String> {
    peer.map(|address| address.ip().to_string())
}

async fn web_app(request: axum::extract::Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let path = request.uri().path();
    if is_protocol_path(path) || has_file_extension(path) {
        return crate::error::not_found("not_found", "not found");
    }

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/dist/index.html")),
    )
        .into_response()
}

fn is_protocol_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || path == "/oauth"
        || path.starts_with("/oauth/")
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.starts_with("/health/")
}

fn has_file_extension(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment
            .rsplit_once('.')
            .is_some_and(|(_, extension)| !extension.is_empty())
    })
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

async fn openid_configuration(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut response =
        Json(OpenIdConfiguration::for_issuer(&state.config.issuer_url)).into_response();
    if headers.contains_key(ORIGIN) {
        response.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            axum::http::HeaderValue::from_static("*"),
        );
        response
            .headers_mut()
            .insert(VARY, axum::http::HeaderValue::from_static("Origin"));
    }
    response
}

async fn jwks(State(state): State<AppState>) -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(state.keys.jwks())
}


