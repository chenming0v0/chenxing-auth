use axum::http::{HeaderMap, HeaderValue};
use chenxing_auth::sessions::cookies::{
    CSRF_COOKIE, SESSION_COOKIE, append_clear_cookies, append_login_cookies, csrf_cookie,
    csrf_cookie_for_secure_transport, csrf_token, session_cookie_id_for_secure_transport,
    session_id,
};

#[test]
fn cookies_parse_session_and_csrf_values_separately() {
    let id = "random-session-token";
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={id}; {CSRF_COOKIE}=csrf-value"))
            .expect("valid cookie header"),
    );
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf-value"));

    assert_eq!(session_id(&headers).as_deref(), Some(id));
    assert_eq!(csrf_cookie(&headers).as_deref(), Some("csrf-value"));
    assert_eq!(csrf_token(&headers).as_deref(), Some("csrf-value"));
}

#[test]
fn secure_mode_does_not_accept_local_cookie_names() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("chenxing_session=session; chenxing_csrf=csrf"),
    );

    assert_eq!(session_cookie_id_for_secure_transport(&headers, true), None);
    assert_eq!(csrf_cookie_for_secure_transport(&headers, true), None);
    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false).as_deref(),
        Some("session")
    );
    assert_eq!(
        csrf_cookie_for_secure_transport(&headers, false).as_deref(),
        Some("csrf")
    );
}

#[test]
fn logout_cookies_are_expired_for_the_browser() {
    let mut headers = HeaderMap::new();
    append_clear_cookies(&mut headers, true).expect("valid logout cookies");

    let values = headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().expect("cookie header").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|value| value.contains("Max-Age=0")));
    assert!(
        values
            .iter()
            .any(|value| value.starts_with("__Host-chenxing_session="))
    );
    assert!(
        values
            .iter()
            .any(|value| value.starts_with("__Host-chenxing_csrf="))
    );
    assert!(values.iter().all(|value| value.contains("Secure")));
    assert!(values.iter().all(|value| value.contains("Path=/")));
    assert!(values.iter().all(|value| !value.contains("Domain=")));
}

#[test]
fn loopback_development_cookies_keep_http_compatibility() {
    let mut headers = HeaderMap::new();
    append_login_cookies(&mut headers, "session", "csrf", 3600, false)
        .expect("valid login cookies");

    let values = headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().expect("cookie header").to_owned())
        .collect::<Vec<_>>();
    assert!(
        values
            .iter()
            .any(|value| value.starts_with("chenxing_session="))
    );
    assert!(
        values
            .iter()
            .any(|value| value.starts_with("chenxing_csrf="))
    );
    assert!(values.iter().all(|value| !value.contains("Secure")));
}
