use axum::{
    extract::{Form, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::{authorization::current_admin_permission, domain::AdminPermission};
use crate::{error, state::AppState, web};

pub async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    let body = "<main><h1>辰星认证中枢管理后台</h1><nav><a href=\"/admin/users\">用户管理</a> · <a href=\"/admin/clients\">Client 管理</a> · <a href=\"/admin/settings/oauth\">OAuth 提供商设置</a> · <a href=\"/admin/audit\">审计日志</a></nav><p>请使用管理 API 执行具体操作。</p></main>";
    Html(web::page("管理后台", body)).into_response()
}

pub async fn login_page() -> Response {
    let body = "<main><h1>管理员登录</h1><form method=\"post\" action=\"/admin/login\"><label>用户名<input name=\"username\" required></label><label>密码<input name=\"password\" type=\"password\" required></label><button type=\"submit\">登录</button></form></main>";
    Html(web::page("管理员登录", body)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct AdminLoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<AdminLoginForm>,
) -> Response {
    let Ok((admin_id, _role)) = state
        .admins
        .authenticate(&form.username, &form.password)
        .await
    else {
        return (StatusCode::UNAUTHORIZED, Html(web::page("管理员登录", "<main><h1>登录失败</h1><p>管理员用户名或密码不正确。</p><a href=\"/admin/login\">返回登录</a></main>"))).into_response();
    };
    let session = match state
        .admin_sessions
        .create(
            admin_id,
            std::time::Duration::from_secs(state.config.session_ttl_seconds),
        )
        .await
    {
        Ok(session) => session,
        Err(redis_error) => {
            tracing::error!(error = %redis_error, "failed to create dashboard admin session");
            return error::internal();
        }
    };
    let mut response = Redirect::to("/admin").into_response();
    crate::sessions::cookies::append_named_login_cookies(
        response.headers_mut(),
        super::session::ADMIN_SESSION_COOKIE,
        super::session::ADMIN_CSRF_COOKIE,
        session.id,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    response
}

pub async fn protected_placeholder(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    Html(web::page(
        "管理后台",
        "<main><h1>管理后台</h1><p>请使用对应的 JSON 管理接口。</p></main>",
    ))
    .into_response()
}
