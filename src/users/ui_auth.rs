use axum::{http::HeaderMap, response::Response};
use uuid::Uuid;

use crate::{
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug)]
pub(crate) struct UserContext {
    pub user_id: UserId,
    pub session: Session,
}

pub(crate) async fn current_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserContext, Response> {
    let Some(session_id) = cookies::cookie_value_by_name(headers, cookies::SESSION_COOKIE)
        .and_then(|value| Uuid::parse_str(&value).ok())
    else {
        return Err(error::unauthorized(
            "login_required",
            "an authenticated session is required",
        ));
    };
    let Some(session) = state
        .sessions
        .find(session_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(error::unauthorized(
            "invalid_session",
            "user session is invalid",
        ));
    };
    if !session.is_active() {
        return Err(error::unauthorized(
            "invalid_session",
            "user session is invalid",
        ));
    }
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| error::unauthorized("invalid_session", "user session is invalid"))?;
    let Some(profile) = state
        .users
        .find_profile(user_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(error::unauthorized(
            "invalid_session",
            "user account is invalid",
        ));
    };
    if profile.status != "active" {
        return Err(error::unauthorized(
            "user_disabled",
            "user account is disabled",
        ));
    }
    Ok(UserContext { user_id, session })
}

pub(crate) async fn mutation_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserContext, ()> {
    let context = current_user(state, headers).await.map_err(|_| ())?;
    if !user_csrf_valid(headers, &context.session) {
        return Err(());
    }
    Ok(context)
}

pub(crate) async fn mutation_error(state: &AppState, headers: &HeaderMap) -> Response {
    match current_user(state, headers).await {
        Err(response) => response,
        Ok(context) if !user_csrf_valid(headers, &context.session) => {
            error::bad_request("csrf_invalid", "CSRF token is invalid")
        }
        Ok(_) => error::internal(),
    }
}

pub(crate) fn user_csrf_valid(headers: &HeaderMap, session: &Session) -> bool {
    let Some(cookie) = cookies::csrf_cookie(headers) else {
        return false;
    };
    let Some(header) = cookies::csrf_token(headers) else {
        return false;
    };
    cookie == header && session.validates_csrf(&header)
}
