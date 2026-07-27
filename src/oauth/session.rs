use axum::http::HeaderMap;
use uuid::Uuid;

use crate::{sessions::cookies, state::AppState};

pub async fn session_user_id(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let session_id = session_id_from_headers(headers)?;
    let session = state.sessions.find(session_id).await.ok().flatten()?;
    session.is_active().then_some(session.user_id)
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    cookies::session_id(headers)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use uuid::Uuid;

    use super::session_id_from_headers;

    #[test]
    fn authorization_session_accepts_browser_cookie() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("chenxing_session={session_id}"))
                .expect("valid cookie header"),
        );

        assert_eq!(session_id_from_headers(&headers), Some(session_id));
    }
}
