//! 管理员、用户权限、套餐和审计查询路由。

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::{
    admin::auth_handlers::create_admin,
    admin::factor_handlers::{auth_factor_key_health, reset_user_totp_factor, user_auth_factors},
    admin::management_handlers::{
        list_admins, list_audit, list_users, set_user_role, set_user_status,
    },
    admin::passkey_recovery::reset_user_passkey_factor,
    admin::plan_handlers::{
        archive_plan, archive_quota_addon, assign_plan, create_plan, create_quota_addon,
        list_plans, list_quota_addons, restore_plan, update_plan, update_quota_addon,
    },
    admin::ui_handlers::{admin_me, admin_overview, query_audit, query_clients, query_users},
    admin::user_creation::create_user,
    admin::wallet_handlers::credit_user_wallet,
    state::AppState,
};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
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
        // 密钥退役或认证器丢失时，保留不依赖已有因子的管理恢复出口。
        .route(
            "/api/v1/admin/users/{user_id}/auth-factors/totp",
            delete(reset_user_totp_factor),
        )
        .route(
            "/api/v1/admin/users/{user_id}/auth-factors/passkey",
            delete(reset_user_passkey_factor),
        )
        .route(
            "/api/v1/admin/auth-factors/key-health",
            get(auth_factor_key_health),
        )
        .route("/api/v1/admin/users/{user_id}/plan", post(assign_plan))
        .route(
            "/api/v1/admin/users/{user_id}/wallet/credit",
            post(credit_user_wallet),
        )
        .route("/api/v1/admin/plans", get(list_plans).post(create_plan))
        .route("/api/v1/admin/plans/{id}", put(update_plan))
        .route("/api/v1/admin/plans/{id}/archive", post(archive_plan))
        .route("/api/v1/admin/plans/{id}/restore", post(restore_plan))
        .route(
            "/api/v1/admin/plans/{id}/quota-addons",
            get(list_quota_addons).post(create_quota_addon),
        )
        .route("/api/v1/admin/quota-addons/{id}", put(update_quota_addon))
        .route(
            "/api/v1/admin/quota-addons/{id}/archive",
            post(archive_quota_addon),
        )
        .route("/api/v1/admin/audit", get(list_audit))
        .route("/api/v1/admin/overview", get(admin_overview))
        .route("/api/v1/admin/users/query", get(query_users))
        .route("/api/v1/admin/clients/query", get(query_clients))
        .route("/api/v1/admin/audit/query", get(query_audit))
}
