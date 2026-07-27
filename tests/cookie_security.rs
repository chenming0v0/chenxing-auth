use axum::http::{HeaderMap, HeaderValue};
use chenxing_auth::sessions::cookies::{csrf_cookie, csrf_token, session_id};
use uuid::Uuid;

#[test]
fn cookies_parse_session_and_csrf_values_separately() {
    let id = Uuid::new_v4();
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("chenxing_session={id}; chenxing_csrf=csrf-value"))
            .expect("valid cookie header"),
    );
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf-value"));

    assert_eq!(session_id(&headers), Some(id));
    assert_eq!(csrf_cookie(&headers).as_deref(), Some("csrf-value"));
    assert_eq!(csrf_token(&headers).as_deref(), Some("csrf-value"));
}
