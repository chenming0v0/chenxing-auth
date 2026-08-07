use axum::http::HeaderMap;
use thiserror::Error;

use crate::{
    sessions::store::SessionStoreError,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::{domain::UserId, service::UserServiceError},
};

#[derive(Debug, Error)]
pub enum SessionLookupError {
    #[error("session store operation failed: {0}")]
    Store(#[from] SessionStoreError),
    #[error("session user lookup failed: {0}")]
    User(#[from] UserServiceError),
}

pub async fn session_for_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Session>, SessionLookupError> {
    let Some(session_token) =
        session_id_from_headers(
            headers,
            state.config.oauth_session_header_enabled,
            state.config.cookie_secure,
        )
    else {
        return Ok(None);
    };
    let Some(session) = state.sessions.find(&session_token).await? else {
        return Ok(None);
    };
    if !session.is_active() {
        return Ok(None);
    }
    if active_user_id(state, &session.user_id).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(session))
}

pub async fn session_user_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, SessionLookupError> {
    session_for_headers(state, headers)
        .await
        .map(|session| session.map(|session| session.user_id))
}

pub async fn active_user_id(
    state: &AppState,
    user_id: &str,
) -> Result<Option<UserId>, UserServiceError> {
    let Ok(user_id) = user_id.parse::<UserId>() else {
        return Ok(None);
    };
    let Some(profile) = state.users.find_profile(user_id).await? else {
        return Ok(None);
    };
    Ok((profile.status == "active").then_some(user_id))
}

fn session_id_from_headers(
    headers: &HeaderMap,
    allow_header: bool,
    secure: bool,
) -> Option<String> {
    let cookie = cookies::session_cookie_id_for_secure_transport(headers, secure);
    let header = cookies::session_header_id(headers);
    if cookie.is_some() && header.is_some() && cookie != header {
        return None;
    }
    cookie.or_else(|| allow_header.then_some(header).flatten())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::session_id_from_headers;

    #[test]
    fn authorization_session_accepts_browser_cookie() {
        let session_id = "random-session-token";
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("__Host-chenxing_session={session_id}"))
                .expect("valid cookie header"),
        );

        assert_eq!(
            session_id_from_headers(&headers, false, true).as_deref(),
            Some(session_id)
        );
    }

    #[test]
    fn authorization_session_header_requires_explicit_compatibility_flag() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("header-session-token"),
        );

        assert_eq!(session_id_from_headers(&headers, false, true), None);
        assert_eq!(
            session_id_from_headers(&headers, true, true).as_deref(),
            Some("header-session-token")
        );
    }

    #[test]
    fn mismatched_cookie_and_header_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("__Host-chenxing_session=cookie-session-token"),
        );
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("header-session-token"),
        );

        assert_eq!(session_id_from_headers(&headers, true, true), None);
    }
}
