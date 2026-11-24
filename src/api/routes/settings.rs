//! 管理配置、外部身份提供方以及邀请和兑换码路由。

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::{
    admin::invitation_code_handlers::{
        create_invitation_codes, disable_invitation_code, get_invitation_code,
        list_invitation_codes,
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
    admin::web_handlers::login_page,
    state::AppState,
    wallet::redemption_handlers::{
        create_redemption_codes, disable_redemption_code, get_redemption_code,
        list_redemption_codes,
    },
};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
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
            "/api/v1/admin/registration-invitation-codes/{id}",
            get(get_invitation_code),
        )
        .route(
            "/api/v1/admin/registration-invitation-codes/{id}/disable",
            post(disable_invitation_code),
        )
        .route(
            "/api/v1/admin/wallet/redemption-codes",
            get(list_redemption_codes).post(create_redemption_codes),
        )
        .route(
            "/api/v1/admin/wallet/redemption-codes/{id}",
            get(get_redemption_code),
        )
        .route(
            "/api/v1/admin/wallet/redemption-codes/{id}/disable",
            post(disable_redemption_code),
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
        .route("/api/v1/admin/oauth/providers/{slug}", put(update_provider))
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
}
