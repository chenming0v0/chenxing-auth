use axum::{
    Form,
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::helpers::{html_error, pending_request_exists};
use crate::{
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::{domain::LoginInput, service::UserServiceError},
};

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub request_id: Option<String>,
    pub external: Option<String>,
    pub external_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub request_id: Option<String>,
    pub email: String,
    pub password: String,
}

pub async fn login_get(State(state): State<AppState>, Query(query): Query<LoginQuery>) -> Response {
    if let Some(request_id) = query.request_id.as_deref()
        && !pending_request_exists(&state, request_id).await
    {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始登录。",
        );
    }
    let request_id = query.request_id.unwrap_or_default();
    let notice = if query.external.as_deref() == Some("success") {
        "外部账号登录成功。"
    } else if query.external_error.is_some() {
        "外部账号登录未完成，请重试或使用邮箱密码登录。"
    } else {
        ""
    };
    let providers = match state.external_oauth.list().await {
        Ok(providers) => providers
            .into_iter()
            .filter(|provider| provider.status == "active")
            .map(|provider| {
                format!(
                    "<a class=\"provider\" href=\"/auth/external/{}?request_id={}\">使用 {} 登录</a>",
                    crate::web::escape_html(&provider.slug),
                    url::form_urlencoded::byte_serialize(request_id.as_bytes()).collect::<String>(),
                    crate::web::escape_html(&provider.name),
                )
            })
            .collect::<Vec<_>>()
            .join(" "),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list external OAuth providers for login page");
            String::new()
        }
    };
    let external_login = if providers.is_empty() {
        String::new()
    } else {
        format!("<section><h2>其他登录方式</h2>{providers}</section>")
    };
    let body = format!(
        "<main><h1>辰星通行证登录</h1><p>{}</p><form method=\"post\" action=\"/auth/login\"><input type=\"hidden\" name=\"request_id\" value=\"{}\"><label>邮箱<input name=\"email\" type=\"email\" autocomplete=\"username\" required></label><label>密码<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label><button type=\"submit\">登录</button></form>{}<p><a href=\"/\">返回首页</a></p></main>",
        crate::web::escape_html(notice),
        crate::web::escape_html(&request_id),
        external_login,
    );
    Html(crate::web::page("辰星通行证登录", &body)).into_response()
}

pub async fn login_post(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let Some(request_id) = form.request_id.as_deref().filter(|value| !value.is_empty()) else {
        return html_error(axum::http::StatusCode::BAD_REQUEST, "缺少授权请求。");
    };
    if !pending_request_exists(&state, request_id).await {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始登录。",
        );
    }
    let user_id = match state
        .users
        .authenticate(LoginInput {
            email: form.email,
            password: form.password,
        })
        .await
    {
        Ok(user_id) => user_id,
        Err(UserServiceError::InvalidCredentials) => {
            return html_error(axum::http::StatusCode::UNAUTHORIZED, "邮箱或密码不正确。");
        }
        Err(UserServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to authenticate browser login");
            return error::internal();
        }
        Err(other_error) => {
            tracing::error!(error = %other_error, "unexpected browser login failure");
            return error::internal();
        }
    };
    let ttl = std::time::Duration::from_secs(state.config.session_ttl_seconds);
    let session = match Session::new(user_id.to_string(), ttl) {
        Ok(session) => session,
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to create browser session");
            return error::internal();
        }
    };
    if let Err(session_error) = state.sessions.save(&session, ttl).await {
        tracing::error!(error = %session_error, "failed to persist browser session");
        return error::internal();
    }
    state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "channel": "browser"}),
        ))
        .await;
    let mut response =
        Redirect::to(&format!("/oauth/authorize/consent?request_id={request_id}")).into_response();
    cookies::append_login_cookies(
        response.headers_mut(),
        session.id,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    response
}
