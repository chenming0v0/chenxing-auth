//! OAuth Client 管理、应用授权、App Links 发布以及签名密钥管理路由。

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::{
    admin::app_link_handlers as admin_app_link_handlers,
    admin::client_create::create_client,
    admin::handlers::{
        delete_client, disable_client, enable_client, list_clients, rotate_secret, update_client,
    },
    admin::key_handlers::{revoke_signing_key, rotate_signing_key},
    state::AppState,
    users::oauth_client_handlers::{
        create_owned_client, delete_owned_client, disable_owned_client, enable_owned_client,
        list_authorized_apps, list_owned_clients, revoke_authorized_app,
        rotate_owned_client_secret, update_owned_client,
    },
};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/api/v1/auth/oauth-clients",
            get(list_owned_clients).post(create_owned_client),
        )
        .route("/api/v1/auth/authorized-apps", get(list_authorized_apps))
        .route(
            "/api/v1/auth/authorized-apps/{client_id}",
            delete(revoke_authorized_app),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}",
            put(update_owned_client).delete(delete_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/disable",
            post(disable_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/enable",
            post(enable_owned_client),
        )
        .route(
            "/api/v1/auth/oauth-clients/{client_id}/rotate-secret",
            post(rotate_owned_client_secret),
        )
        .route(
            "/api/v1/admin/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}",
            put(update_client).delete(delete_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/disable",
            post(disable_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/enable",
            post(enable_client),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/rotate-secret",
            post(rotate_secret),
        )
        // 管理发布使用 client_id，按数字 App ID 发现仍由不经 Issuer 门禁的 system 路由处理。
        .route(
            "/api/v1/admin/app-links",
            get(admin_app_link_handlers::list_app_links),
        )
        .route(
            "/api/v1/admin/app-links/{client_id}",
            put(admin_app_link_handlers::upsert_app_link)
                .delete(admin_app_link_handlers::delete_app_link),
        )
        .route("/api/v1/admin/keys/rotate", post(rotate_signing_key))
        .route(
            "/api/v1/admin/keys/{key_id}/revoke",
            post(revoke_signing_key),
        )
}
