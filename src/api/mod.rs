use axum::{
    Router,
    http::HeaderMap,
    routing::{delete, get, post},
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

use crate::config::TrustedProxies;

mod discovery;
mod health;
mod static_files;

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

use discovery::{jwks, openid_configuration};
use health::{health, health_live, health_ready};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
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
        // 静态资源与 SPA 回退挂在 fallback 上：fallback_service 只在上面所有
        // 路由都不匹配时才生效，所以 /api/*、/health 等不会被静态服务抢走。
        .fallback_service(static_files::static_service())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// 从请求对端地址和头部解析真实客户端 IP。
///
/// **安全规则**（#111）：
/// - 未配置可信代理或对端不可信 → 用对端地址，忽略 XFF（防伪造）
/// - 对端可信且有 XFF → 从右往左扫描，第一个不可信的 IP 是客户端
///
/// 此函数收敛了项目中所有的源 IP 解析逻辑。OAuth `/token`、TOTP、Passkey
/// 和登录端点都调用它。未配置 `trusted_proxies` 时启动阶段已告警。
pub(crate) fn source_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    trusted_proxies.resolve_client_ip(peer, headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        response::Response,
    };
    use tower::ServiceExt;

    /// 构造完整 Router 并发送一次请求。
    ///
    /// 这些断言在有无 `web/dist` 的环境下都成立：`web/dist` 被 gitignore，
    /// 测试不能依赖真实构建产物是否存在。
    async fn send_request(uri: &str, method: Method) -> Response {
        let request = Request::builder()
            .uri(uri)
            .method(method)
            .body(Body::empty())
            .expect("valid request");

        router(AppState::for_test().await)
            .oneshot(request)
            .await
            .expect("router response")
    }

    /// 只取 content-type 的 MIME 部分，忽略 charset 等参数。
    fn content_type(response: &Response) -> Option<&str> {
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value))
    }

    #[tokio::test]
    async fn spa_routes_serve_the_embedded_index_html() {
        // 客户端路由（React Router）必须拿到 index.html 而不是 404，
        // 且该行为不依赖 web/dist 是否存在，因为 index.html 是编译期内嵌的。
        let response = send_request("/console/developer", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), Some("text/html"));
    }

    #[tokio::test]
    async fn root_path_serves_the_embedded_shell_with_an_explicit_charset() {
        // 根路径必须始终由内嵌 shell 处理，而不是 ServeDir 的目录索引：
        // ServeDir 走 mime_guess，只会给出不带 charset 的 `text/html`，
        // 而调用方（含 tests/web.rs）依赖 `text/html; charset=utf-8`。
        // 这条断言同时锁定“目录索引已关闭”这一配置。
        let response = send_request("/", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn unknown_api_paths_return_json_not_the_spa_shell() {
        // /api 下的未知路径返回 JSON 404，避免客户端把 HTML 当 JSON 解析
        let response = send_request("/api/v1/does-not-exist", Method::GET).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(content_type(&response), Some("application/json"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "not_found");
    }

    #[tokio::test]
    async fn registered_api_routes_are_not_shadowed_by_the_static_service() {
        // 回归保护：静态服务挂在 fallback 上，不能抢走已注册的 API 路由。
        // 该端点要求会话，返回 401 说明请求到达了处理器而不是文件服务。
        let response = send_request("/api/v1/auth/authorized-apps", Method::GET).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_endpoint_is_not_shadowed_by_the_static_service() {
        let response = send_request("/health/live", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), Some("application/json"));
    }

    #[tokio::test]
    async fn missing_static_assets_return_json_not_found() {
        // 缺失的资源路径（带扩展名）返回 JSON 404，而不是 200 + HTML。
        // 否则浏览器会把 index.html 当作 JS 执行并报 MIME 类型错误。
        let response = send_request("/assets/missing-chunk.js", Method::GET).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(content_type(&response), Some("application/json"));
    }

    #[tokio::test]
    async fn post_to_unknown_path_returns_not_found_not_method_not_allowed() {
        // 验证 call_fallback_on_method_not_allowed(true) 生效：
        // 缺少该配置时 ServeDir 会直接返回 405，绕过统一的 404 语义。
        let response = send_request("/unknown-path", Method::POST).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
