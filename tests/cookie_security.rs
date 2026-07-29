use axum::http::{HeaderMap, HeaderValue};
use chenxing_auth::sessions::cookies::{append_clear_cookies, csrf_cookie, csrf_token, session_id};

#[test]
fn cookies_parse_session_and_csrf_values_separately() {
    let id = "random-session-token";
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("chenxing_session={id}; chenxing_csrf=csrf-value"))
            .expect("valid cookie header"),
    );
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf-value"));

    assert_eq!(session_id(&headers).as_deref(), Some(id));
    assert_eq!(csrf_cookie(&headers).as_deref(), Some("csrf-value"));
    assert_eq!(csrf_token(&headers).as_deref(), Some("csrf-value"));
}

#[test]
fn logout_cookies_are_expired_for_the_browser() {
    let mut headers = HeaderMap::new();
    append_clear_cookies(&mut headers, false);

    let values = headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().expect("cookie header").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|value| value.contains("Max-Age=0")));
}
