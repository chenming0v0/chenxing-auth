use axum::{http::HeaderMap, response::Response};

use crate::{
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::domain::{UserId, UserStatus},
};

#[derive(Debug)]
pub struct UserContext {
    pub user_id: UserId,
    pub session: Session,
    pub role: super::domain::UserRole,
}

pub(crate) async fn current_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserContext, Response> {
    let Some(session_token) =
        cookies::session_cookie_id_for_secure_transport(headers, state.config.cookie_secure)
    else {
        return Err(error::unauthorized(
            "login_required",
            "an authenticated session is required",
        ));
    };
    let Some(session) = state
        .sessions
        .find(&session_token)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(invalid_session_response(state, "invalid_session"));
    };
    if !session.is_active_at(state.clock.now()) {
        return Err(invalid_session_response(state, "invalid_session"));
    }
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| invalid_session_response(state, "invalid_session"))?;
    let Some(profile) = state
        .users
        .find_profile(user_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(invalid_session_response(state, "invalid_session"));
    };
    if UserStatus::parse(&profile.status) != Some(UserStatus::Active) {
        return Err(invalid_session_response(state, "user_disabled"));
    }
    Ok(UserContext {
        user_id,
        session,
        role: profile.role,
    })
}

fn invalid_session_response(state: &AppState, code: &'static str) -> Response {
    let message = if code == "user_disabled" {
        "user account is disabled"
    } else {
        "user session is invalid"
    };
    let mut response = error::unauthorized(code, message);
    if let Err(cookie_error) =
        cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)
    {
        tracing::error!(
            error = %cookie_error,
            "failed to build invalid session cookie response"
        );
        return error::internal();
    }
    response
}

/// 校验 CSRF 三者绑定：CSRF Cookie、`X-CSRF-Token` 头部与会话内的令牌。
///
/// 三者都要比对：只查 Cookie 与头部相等无法防御「攻击者写入自己的 Cookie 对」，
/// 只查会话令牌则无法防御「头部缺失但 Cookie 被浏览器自动附带」。
///
/// 调用方是 `crate::api::extract` 中的提取器，handler 不直接调用它 ——
/// 让类型系统而非人工记忆来保证写端点走到这一步。
pub(crate) fn user_csrf_valid(headers: &HeaderMap, session: &Session, secure: bool) -> bool {
    let Some(cookie) = cookies::csrf_cookie_for_secure_transport(headers, secure) else {
        return false;
    };
    let Some(header) = cookies::csrf_token(headers) else {
        return false;
    };
    cookie == header && session.validates_csrf(&header)
}
