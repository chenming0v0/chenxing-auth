use axum::{
    Form,
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::helpers::{html_error, pending_request_exists};
use crate::{
    audit::AuditEvent,
    auth_factors::service::TotpConfirmation,
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::{
        domain::{LoginInput, UserId},
        service::UserServiceError,
    },
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
    #[serde(alias = "email")]
    pub identifier: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BrowserTotpForm {
    pub request_id: String,
    pub login_ticket: String,
    pub code: String,
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
        "<main><h1>辰星通行证登录</h1><p>{}</p><form method=\"post\" action=\"/auth/login\"><input type=\"hidden\" name=\"request_id\" value=\"{}\"><label>用户名或邮箱<input name=\"identifier\" type=\"text\" autocomplete=\"username\" required></label><label>密码<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label><button type=\"submit\">登录</button></form>{}<p><a href=\"/\">返回首页</a></p></main>",
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
            identifier: form.identifier,
            password: form.password,
            totp_code: None,
        })
        .await
    {
        Ok(user_id) => user_id,
        Err(UserServiceError::InvalidCredentials) => {
            return html_error(
                axum::http::StatusCode::UNAUTHORIZED,
                "用户名、邮箱或密码不正确。",
            );
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
    let methods = match state.factors.available_methods(user_id).await {
        Ok(methods) => methods,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load browser login factors");
            return error::internal();
        }
    };
    let setup_required = methods.is_empty();
    let ticket_methods = if setup_required {
        vec![
            crate::auth_factors::domain::FactorMethod::Totp,
            crate::auth_factors::domain::FactorMethod::Passkey,
        ]
    } else {
        methods
    };
    let (ticket_id, _) = match state
        .factors
        .create_login_ticket(user_id, ticket_methods)
        .await
    {
        Ok(ticket) => ticket,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to create browser login ticket");
            return error::internal();
        }
    };
    if let Some(code) = form.totp_code.as_deref() {
        return finish_totp_login(&state, request_id, &ticket_id, code, setup_required).await;
    }
    if setup_required {
        return render_totp_setup(&state, request_id, ticket_id, user_id).await;
    }
    if methods_contains_totp(&state, user_id).await {
        return render_totp_verify(request_id, ticket_id);
    }
    html_error(
        axum::http::StatusCode::BAD_REQUEST,
        "请使用 passkey WebAuthn 接口完成登录。",
    )
}

pub async fn browser_totp_post(
    State(state): State<AppState>,
    Form(form): Form<BrowserTotpForm>,
) -> Response {
    if !pending_request_exists(&state, &form.request_id).await {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始登录。",
        );
    }
    let setup_result = state
        .factors
        .confirm_totp_enrollment(&form.login_ticket, &form.code)
        .await;
    match setup_result {
        Ok(TotpConfirmation::Completed(user_id)) => {
            return complete_browser_login(&state, &form.request_id, user_id, "totp").await;
        }
        Ok(TotpConfirmation::InvalidCode) => {
            return html_error(axum::http::StatusCode::UNAUTHORIZED, "动态验证码不正确。");
        }
        Ok(TotpConfirmation::InvalidTicket) => {}
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to confirm browser TOTP setup");
            return error::internal();
        }
    }
    match state
        .factors
        .verify_totp_login(&form.login_ticket, &form.code)
        .await
    {
        Ok(TotpConfirmation::Completed(user_id)) => {
            complete_browser_login(&state, &form.request_id, user_id, "totp").await
        }
        Ok(TotpConfirmation::InvalidCode) => {
            html_error(axum::http::StatusCode::UNAUTHORIZED, "动态验证码不正确。")
        }
        Ok(TotpConfirmation::InvalidTicket) => {
            html_error(axum::http::StatusCode::BAD_REQUEST, "登录请求已失效。")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to verify browser TOTP");
            error::internal()
        }
    }
}

async fn render_totp_setup(
    state: &AppState,
    request_id: &str,
    ticket_id: String,
    user_id: UserId,
) -> Response {
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load browser TOTP account");
            return error::internal();
        }
    }) else {
        return error::internal();
    };
    let enrollment = match state
        .factors
        .start_totp_enrollment(&ticket_id, &profile.email, "Chenxing Pass")
        .await
    {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => return error::bad_request("invalid_login_ticket", "login request is invalid"),
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start browser TOTP setup");
            return error::internal();
        }
    };
    let Some(qr_svg) = crate::web::totp_qr_svg(enrollment.otpauth_url()) else {
        tracing::error!("failed to render browser TOTP QR code");
        return error::internal();
    };
    let secret = crate::web::escape_html(enrollment.secret_base32());
    let body = format!(
        "<main><h1>设置动态验证码</h1><p>请使用验证器扫描二维码，然后输入当前六位验证码。</p><div class=\"totp-qr\" aria-label=\"TOTP 验证器绑定二维码\">{qr_svg}</div><details><summary>无法扫描？手动输入密钥</summary><div class=\"totp-secret\" data-totp-secret=\"{secret}\"><code>{secret}</code><button type=\"button\" onclick=\"copyTotpSecret(this)\">复制</button></div></details><form method=\"post\" action=\"/auth/login/totp\"><input type=\"hidden\" name=\"request_id\" value=\"{request_id}\"><input type=\"hidden\" name=\"login_ticket\" value=\"{ticket_id}\"><label>动态验证码<input name=\"code\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" required></label><button type=\"submit\">确认登录</button></form><script>async function copyTotpSecret(button){{const value=button.parentElement.dataset.totpSecret;try{{if(navigator.clipboard?.writeText){{await navigator.clipboard.writeText(value);}}else{{const textarea=document.createElement('textarea');textarea.value=value;textarea.setAttribute('readonly','');textarea.style.position='fixed';textarea.style.opacity='0';document.body.appendChild(textarea);textarea.select();if(!document.execCommand('copy')) throw new Error('copy failed');textarea.remove();}}button.textContent='已复制';window.setTimeout(() => button.textContent='复制',1600);}}catch{{button.textContent='复制失败';window.setTimeout(() => button.textContent='复制',1600);}}}}</script></main>",
        qr_svg = qr_svg,
        secret = secret,
        request_id = crate::web::escape_html(request_id),
        ticket_id = crate::web::escape_html(&ticket_id),
    );
    Html(crate::web::page("设置动态验证码", &body)).into_response()
}

fn render_totp_verify(request_id: &str, ticket_id: String) -> Response {
    let body = format!(
        "<main><h1>输入动态验证码</h1><form method=\"post\" action=\"/auth/login/totp\"><input type=\"hidden\" name=\"request_id\" value=\"{}\"><input type=\"hidden\" name=\"login_ticket\" value=\"{}\"><label>动态验证码<input name=\"code\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" required></label><button type=\"submit\">继续</button></form></main>",
        crate::web::escape_html(request_id),
        crate::web::escape_html(&ticket_id),
    );
    Html(crate::web::page("输入动态验证码", &body)).into_response()
}

async fn finish_totp_login(
    state: &AppState,
    request_id: &str,
    ticket_id: &str,
    code: &str,
    setup_required: bool,
) -> Response {
    let result = if setup_required {
        state.factors.confirm_totp_enrollment(ticket_id, code).await
    } else {
        state.factors.verify_totp_login(ticket_id, code).await
    };
    match result {
        Ok(TotpConfirmation::Completed(user_id)) => {
            complete_browser_login(state, request_id, user_id, "totp").await
        }
        Ok(TotpConfirmation::InvalidCode) => {
            html_error(axum::http::StatusCode::UNAUTHORIZED, "动态验证码不正确。")
        }
        Ok(TotpConfirmation::InvalidTicket) => {
            html_error(axum::http::StatusCode::BAD_REQUEST, "登录请求已失效。")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish browser TOTP login");
            error::internal()
        }
    }
}

async fn methods_contains_totp(state: &AppState, user_id: UserId) -> bool {
    state
        .factors
        .available_methods(user_id)
        .await
        .map(|methods| methods.contains(&crate::auth_factors::domain::FactorMethod::Totp))
        .unwrap_or(false)
}

async fn complete_browser_login(
    state: &AppState,
    request_id: &str,
    user_id: UserId,
    factor: &str,
) -> Response {
    let ttl = std::time::Duration::from_secs(state.config.session_ttl_seconds);
    let mut session = match Session::new(user_id.to_string(), ttl) {
        Ok(session) => session,
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to create browser session");
            return error::internal();
        }
    };
    if let Err(session_error) = state.sessions.save(&mut session, ttl).await {
        tracing::error!(error = %session_error, "failed to persist browser session");
        return error::internal();
    }
    let Some(mut pending) = state
        .authorization_requests
        .find(request_id)
        .await
        .ok()
        .flatten()
    else {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始登录。",
        );
    };
    pending.session_id = Some(session.token.clone());
    if let Err(store_error) = state.authorization_requests.save(&pending).await {
        tracing::error!(error = %store_error, "failed to bind authorization request to session");
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
            serde_json::json!({"result": "success", "channel": "browser", "factor": factor}),
        ))
        .await;
    let mut response =
        Redirect::to(&format!("/oauth/authorize/consent?request_id={request_id}")).into_response();
    cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    response
}
