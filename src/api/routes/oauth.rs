//! OAuth/OIDC 协议、外部身份登录及资源服务登录票路由。

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
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
    resource_services::exchange::exchange,
    state::AppState,
    users::handlers::registration_status,
};

use super::super::discovery::{jwks, jwks_options, openid_configuration};

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks).options(jwks_options))
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
        .route(
            "/api/v1/auth/external-providers",
            get(list_public_providers),
        )
        // 匿名状态仍由 handler 计算开关与 Issuer 就绪，缺少 Issuer 时返回 enabled=false。
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
        .route("/api/v2/auth/chenxing/exchange", post(exchange))
}
