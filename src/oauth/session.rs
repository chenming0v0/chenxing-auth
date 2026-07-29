use axum::http::HeaderMap;

use crate::{
    sessions::{cookies, domain::Session},
    state::AppState,
};

pub async fn session_for_headers(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let session_token = session_id_from_headers(headers)?;
    let session = state.sessions.find(&session_token).await.ok().flatten()?;
    session.is_active().then_some(session)
}

pub async fn session_user_id(state: &AppState, headers: &HeaderMap) -> Option<String> {
    session_for_headers(state, headers)
        .await
        .map(|session| session.user_id)
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    cookies::session_id(headers)
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
            HeaderValue::from_str(&format!("chenxing_session={session_id}"))
                .expect("valid cookie header"),
        );

        assert_eq!(
            session_id_from_headers(&headers).as_deref(),
            Some(session_id)
        );
    }
}
