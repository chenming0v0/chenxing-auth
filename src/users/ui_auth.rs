use axum::{http::HeaderMap, response::Response};

use crate::{
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::domain::{UserId, UserStatus},
};

#[derive(Debug)]
pub(crate) struct UserContext {
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
    if !session.is_active() {
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
    cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure);
    response
}

pub(crate) async fn mutation_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserContext, ()> {
    let context = current_user(state, headers).await.map_err(|_| ())?;
    if !user_csrf_valid(headers, &context.session, state.config.cookie_secure) {
        return Err(());
    }
    Ok(context)
}

pub(crate) async fn mutation_error(state: &AppState, headers: &HeaderMap) -> Response {
    match current_user(state, headers).await {
        Err(response) => response,
        Ok(context) if !user_csrf_valid(headers, &context.session, state.config.cookie_secure) => {
            error::bad_request("csrf_invalid", "CSRF token is invalid")
        }
        Ok(_) => error::internal(),
    }
}

pub(crate) fn user_csrf_valid(headers: &HeaderMap, session: &Session, secure: bool) -> bool {
    let Some(cookie) = cookies::csrf_cookie_for_secure_transport(headers, secure) else {
        return false;
    };
    let Some(header) = cookies::csrf_token(headers) else {
        return false;
    };
    cookie == header && session.validates_csrf(&header)
}
