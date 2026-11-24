//! 本地登录、账户资料、安全因子、会话及用户钱包路由。

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
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
    state::AppState,
    users::avatar_handlers::{
        current_user_avatar, delete_current_user_avatar, upload_current_user_avatar,
    },
    users::avatar_image::MAX_UPLOAD_BYTES,
    users::email_change_handlers::{confirm_email_change, start_email_change},
    users::entitlements_handlers::current_entitlements,
    users::handlers::{login_user, register_user, revoke_session},
    users::security_event_handlers::{get_security_event, list_security_events},
    users::ui_handlers::{
        auth_status, change_current_user_password, current_user_profile, list_user_sessions,
        revoke_user_session, update_current_user_profile,
    },
    wallet::handlers::{
        get_wallet, list_plan_catalog, list_quota_addon_catalog, list_wallet_ledger, purchase_plan,
        purchase_quota_addon,
    },
    wallet::redemption_handlers::redeem_wallet_code,
};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
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
        // 头像路由单独放宽体积限制，其他 JSON 接口仍受默认的 2 MiB 上限约束。
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
        .route("/api/v1/auth/wallet", get(get_wallet))
        .route("/api/v1/auth/wallet/ledger", get(list_wallet_ledger))
        .route("/api/v1/auth/plans/catalog", get(list_plan_catalog))
        .route("/api/v1/auth/wallet/purchase", post(purchase_plan))
        .route(
            "/api/v1/auth/quota-addons/catalog",
            get(list_quota_addon_catalog),
        )
        .route(
            "/api/v1/auth/quota-addons/purchase",
            post(purchase_quota_addon),
        )
        .route("/api/v1/auth/wallet/redeem", post(redeem_wallet_code))
        .route("/api/v1/auth/security-events", get(list_security_events))
        .route(
            "/api/v1/auth/security-events/{event_id}",
            get(get_security_event),
        )
        .route("/api/v1/auth/sessions", get(list_user_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            delete(revoke_user_session),
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
        .route("/api/v1/auth/session", delete(revoke_session))
}
