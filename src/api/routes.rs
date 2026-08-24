use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
    admin::auth_handlers::create_admin,
    admin::factor_handlers::{auth_factor_key_health, reset_user_totp_factor, user_auth_factors},
    admin::handlers::{
        create_client, disable_client, enable_client, list_clients, rotate_secret, update_client,
    },
    admin::invitation_code_handlers::{
        create_invitation_codes, disable_invitation_code, list_invitation_codes,
    },
    admin::key_handlers::{revoke_signing_key, rotate_signing_key},
    admin::management_handlers::{
        list_admins, list_audit, list_users, set_user_role, set_user_status,
    },
    admin::passkey_recovery::reset_user_passkey_factor,
    admin::plan_handlers::{
        archive_plan, assign_plan, create_plan, list_plans, restore_plan, update_plan,
    },
    admin::provider_handlers::{
        create_provider, disable_provider, enable_provider, list_providers, update_provider,
    },
    admin::provider_web_handlers::oauth_settings,
    admin::registration_settings_handlers::{
        get_registration_setting, update_registration_setting,
    },
    admin::settings_handlers::{
        get_email_policy_setting, get_passkey_setting, get_registration_email,
        get_security_limits_setting, get_session_lifetime_setting, get_smtp_setting,
        update_email_policy_setting, update_passkey_setting, update_registration_email,
        update_security_limits_setting, update_session_lifetime_setting, update_smtp_setting,
    },
    admin::ui_handlers::{admin_me, admin_overview, query_audit, query_clients, query_users},
    admin::user_creation::create_user,
    admin::web_handlers::login_page,
    auth_factors::handlers::{
        confirm_totp_setup, finish_discoverable_passkey_authentication,
        finish_passkey_authentication, finish_passkey_registration, login_totp,
        start_discoverable_passkey_authentication, start_passkey_authentication,
        start_passkey_registration, start_totp_setup,
    },
    auth_factors::security_handlers::{
        cancel_security_factor_enrollment, confirm_security_totp_enrollment,
        current_security_factors, finish_security_passkey_registration,
        remove_security_passkey_factor, remove_security_totp_factor,
        start_security_passkey_registration, start_security_totp_enrollment,
    },
    oauth::handlers::{authorize, authorize_post, token},
    oauth::providers::handlers::{
        external_binding_callback, external_callback, list_linked_identities,
        list_public_providers, start_external_binding, start_external_login,
        unlink_external_identity,
    },
    oauth::revocation_handler::revoke,
    oauth::ui_handlers::{
        bind_authorization_request, decide_authorization_request, inspect_authorization_request,
    },
    oauth::userinfo::{userinfo, userinfo_post},
    state::AppState,
    users::avatar_handlers::{
        current_user_avatar, delete_current_user_avatar, upload_current_user_avatar,
    },
    users::avatar_image::MAX_UPLOAD_BYTES,
    users::email_change_handlers::{confirm_email_change, start_email_change},
    users::entitlements_handlers::current_entitlements,
    users::handlers::{login_user, register_user, registration_status, revoke_session},
    users::oauth_client_handlers::{
        create_owned_client, disable_owned_client, enable_owned_client, list_authorized_apps,
        list_owned_clients, revoke_authorized_app, rotate_owned_client_secret, update_owned_client,
    },
    users::security_event_handlers::{get_security_event, list_security_events},
    users::ui_handlers::{
        auth_status, change_current_user_password, current_user_profile, list_user_sessions,
        revoke_user_session, update_current_user_profile,
    },
};

use super::discovery::{jwks, openid_configuration};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route(
            "/.well-known/jwks.json",
            get(jwks).options(super::discovery::jwks_options),
        )
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
        .route(
            "/api/v1/auth/passkeys/discoverable/start",
            post(start_discoverable_passkey_authentication),
        )
        .route(
            "/api/v1/auth/passkeys/discoverable/finish",
            post(finish_discoverable_passkey_authentication),
        )
        .route("/api/v1/auth/status", get(auth_status))
        .route(
            "/api/v1/auth/me",
            get(current_user_profile).patch(update_current_user_profile),
        )
        // 头像上传体远大于 JSON 请求，需要单独放宽 axum 默认的 2 MiB 体上限。
        // 该 layer 只挂在本路由上：全局放宽会让每个 JSON 端点都能被灌入大体积请求。
        .route(
            "/api/v1/auth/me/avatar",
            get(current_user_avatar)
                .put(upload_current_user_avatar)
                .delete(delete_current_user_avatar)
                .route_layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/api/v1/auth/email-change/start", post(start_email_change))
        .route(
            "/api/v1/auth/email-change/confirm",
            post(confirm_email_change),
        )
        .route("/api/v1/auth/password", post(change_current_user_password))
        .route("/api/v1/auth/entitlements", get(current_entitlements))
        .route("/api/v1/auth/security-events", get(list_security_events))
        .route(
            "/api/v1/auth/security-events/{event_id}",
            get(get_security_event),
        )
        .route("/api/v1/auth/sessions", get(list_user_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            axum::routing::delete(revoke_user_session),
        )
        .route(
            "/api/v1/auth/security/factors",
            get(current_security_factors),
        )
        .route(
            "/api/v1/auth/security/totp/enrollment/start",
            post(start_security_totp_enrollment),
        )
        .route(
            "/api/v1/auth/security/factor/enrollment/cancel",
            post(cancel_security_factor_enrollment),
        )
        .route(
            "/api/v1/auth/security/totp/enrollment/confirm",
            post(confirm_security_totp_enrollment),
        )
        .route(
            "/api/v1/auth/security/passkeys/registration/start",
            post(start_security_passkey_registration),
        )
        .route(
            "/api/v1/auth/security/passkeys/registration/finish",
            post(finish_security_passkey_registration),
        )
        .route(
            "/api/v1/auth/security/factors/totp",
            delete(remove_security_totp_factor),
        )
        .route(
            "/api/v1/auth/security/factors/passkey",
            delete(remove_security_passkey_factor),
        )
        .route("/api/v1/admin/admins", get(list_admins).post(create_admin))
        .route("/api/v1/admin/auth/me", get(admin_me))
        .route("/api/v1/admin/users", get(list_users).post(create_user))
        .route(
            "/api/v1/admin/users/{user_id}/{status}",
            post(set_user_status),
        )
        .route("/api/v1/admin/users/{user_id}/role", post(set_user_role))
        .route(
            "/api/v1/admin/users/{user_id}/auth-factors",
            get(user_auth_factors),
        )
        // 因子重置是 #258 的恢复出口：kid 退役后种子不可解，只能丢弃密文重新注册。
        .route(
            "/api/v1/admin/users/{user_id}/auth-factors/totp",
            delete(reset_user_totp_factor),
        )
        // Passkey 重置是 #460 的恢复出口：Passkey-only 账号丢了认证器后，
        // 系统 Token 通道不依赖现有 Session / Passkey。
        .route(
            "/api/v1/admin/users/{user_id}/auth-factors/passkey",
            delete(reset_user_passkey_factor),
        )
        .route(
            "/api/v1/admin/auth-factors/key-health",
            get(auth_factor_key_health),
        )
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
            "/api/v1/admin/settings/registration",
            get(get_registration_setting).put(update_registration_setting),
        )
        .route(
            "/api/v1/admin/registration-invitation-codes",
            get(list_invitation_codes).post(create_invitation_codes),
        )
        .route(
            "/api/v1/admin/registration-invitation-codes/{id}/disable",
            post(disable_invitation_code),
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
            "/api/v1/admin/settings/session-lifetime",
            get(get_session_lifetime_setting).put(update_session_lifetime_setting),
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
        .route("/admin/login", get(login_page))
        .route("/admin/settings/oauth", get(oauth_settings))
        .route(
            "/api/v1/auth/external-providers",
            get(list_public_providers),
        )
        // 匿名注册状态：有效值（存储开关 AND Issuer 就绪），前端据此决定是否
        // 展示注册入口。不在 issuer 门禁的「必须配置」清单内——Issuer 缺失时
        // 照常返回 enabled=false，而不是 503。
        .route("/api/v1/auth/registration-status", get(registration_status))
        .route("/auth/external/{slug}", get(start_external_login))
        .route("/auth/external/{slug}/callback", get(external_callback))
        .route(
            "/api/v1/auth/external-identities",
            get(list_linked_identities),
        )
        .route(
            "/api/v1/auth/external-identities/{slug}/bind",
            post(start_external_binding),
        )
        .route(
            "/auth/external/{slug}/bind/callback",
            get(external_binding_callback),
        )
        .route(
            "/api/v1/auth/external-identities/{slug}",
            delete(unlink_external_identity),
        )
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
}
