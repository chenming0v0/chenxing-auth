use axum::{
    Router,
    routing::{get, post},
};

use crate::state::AppState;

use super::{admin_handlers, portal_handlers};

pub(crate) fn register(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/api/v1/admin/account-portal/providers",
            get(admin_handlers::list).post(admin_handlers::create),
        )
        .route(
            "/api/v1/admin/account-portal/providers/{id}",
            get(admin_handlers::get).put(admin_handlers::update),
        )
        .route(
            "/api/v1/admin/account-portal/providers/{id}/enable",
            post(admin_handlers::enable),
        )
        .route(
            "/api/v1/admin/account-portal/providers/{id}/disable",
            post(admin_handlers::disable),
        )
        .route(
            "/api/v1/auth/account-portal/providers",
            get(portal_handlers::list_providers),
        )
        .route(
            "/api/v1/auth/account-portal/bindings",
            get(portal_handlers::list_bindings).post(portal_handlers::create_binding),
        )
        .route(
            "/api/v1/auth/account-portal/bindings/{id}",
            get(portal_handlers::get_binding).delete(portal_handlers::unlink_binding),
        )
        .route(
            "/api/v1/auth/account-portal/bindings/{id}/refresh",
            post(portal_handlers::refresh_binding),
        )
        .route(
            "/api/v1/auth/account-portal/bindings/{id}/sync",
            post(portal_handlers::sync_binding),
        )
}
