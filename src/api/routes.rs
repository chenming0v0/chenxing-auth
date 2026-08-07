use axum::{
    Router,
    http::StatusCode,
    routing::{delete, get, post},
};
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::{
    admin::auth_handlers::{bootstrap_admin, bootstrap_status, create_admin},
    admin::handlers::{
        create_client, disable_client, enable_client, list_clients, rotate_secret, update_client,
    },
    admin::key_handlers::{revoke_signing_key, rotate_signing_key},
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
        get_email_policy_setting, get_passkey_setting, get_registration_email,
        get_security_limits_setting, get_smtp_setting, update_email_policy_setting,
        update_passkey_setting, update_registration_email, update_security_limits_setting,
        update_smtp_setting,
    },
    admin::ui_handlers::{admin_me, admin_overview, query_audit, query_clients, query_users},
    admin::user_creation::create_user,
    admin::web_handlers::{
        audit_page, clients_page, dashboard, login_page, login_submit, users_page,
    },
    auth_factors::handlers::{
        confirm_totp_setup, finish_passkey_authentication, finish_passkey_registration, login_totp,
        start_passkey_authentication, start_passkey_registration, start_totp_setup,
    },
    oauth::handlers::{authorize, authorize_post, token},
    oauth::providers::handlers::{external_callback, list_public_providers, start_external_login},
    oauth::revocation_handler::revoke,
    oauth::ui_handlers::{
        bind_authorization_request, decide_authorization_request, inspect_authorization_request,
    },
    oauth::userinfo::{userinfo, userinfo_post},
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

use super::{
    discovery::{jwks, openid_configuration},
    health::{health, health_live, health_ready},
};

pub(super) fn register(router: Router<AppState>, request_timeout: Duration) -> Router<AppState> {
    router
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(authorize).post(authorize_post))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/userinfo", get(userinfo).post(userinfo_post))
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
        .route("/api/v1/admin/users", get(list_users).post(create_user))
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
            "/api/v1/admin/settings/security-limits",
            get(get_security_limits_setting).put(update_security_limits_setting),
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
        .route(
            "/api/v1/admin/keys/{key_id}/revoke",
            axum::routing::post(revoke_signing_key),
        )
        // Health probes have their own 2s dependency budget. The static fallback may
        // stream files, so neither should inherit this handler-future timeout.
        .route_layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
}
