use axum::http::{HeaderMap, HeaderValue};
use chenxing_auth::sessions::cookies::{
    CSRF_COOKIE, CookieReadError, SESSION_COOKIE, append_clear_cookies, append_login_cookies,
    csrf_cookie, csrf_cookie_for_secure_transport, csrf_token,
    session_cookie_id_for_secure_transport,
};

/// 会话取值只有一条公开入口：按传输安全性选名的 Cookie 读取。
///
/// #306：`session_id`（头部优先、无条件回退 Cookie）已被删除，因为它绕过
/// `OAUTH_SESSION_HEADER_ENABLED` 开关与头部/Cookie 冲突检查。
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

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, true)
            .expect("session cookie parse")
            .as_deref(),
        Some(id)
    );
    assert_eq!(
        csrf_cookie(&headers).expect("csrf cookie parse").as_deref(),
        Some("csrf-value")
    );
    assert_eq!(csrf_token(&headers).as_deref(), Some("csrf-value"));
}

/// #306：请求头部不能成为绕过配置开关的第二条会话入口。
///
/// 这里断言的是源码事实而不是运行时行为：只要 `sessions::cookies` 里不存在
/// 「头部优先、回退 Cookie」的便捷函数，任何调用点就不可能绕过
/// `oauth::session::session_id_from_headers` 的开关与冲突检查。
#[test]
fn no_ungated_header_or_cookie_session_helper_exists() {
    const COOKIES_MODULE: &str = include_str!("../src/sessions/cookies.rs");
    const OAUTH_SESSION_MODULE: &str = include_str!("../src/oauth/session.rs");

    assert!(
        !COOKIES_MODULE.contains("pub fn session_id("),
        "sessions::cookies must not expose an ungated session_id helper"
    );
    assert!(
        !COOKIES_MODULE.contains("session_header_id(headers).or_else("),
        "no helper may fall back from the compatibility header to the cookie unconditionally"
    );
    assert!(
        !COOKIES_MODULE.contains("headers.get(COOKIE)"),
        "security cookie readers must not take the first Cookie header"
    );
    assert!(
        COOKIES_MODULE.contains("read_named_cookie(headers,"),
        "every security cookie reader must share the Result parse boundary"
    );
    assert!(
        OAUTH_SESSION_MODULE.contains("fn session_id_from_headers("),
        "the configured header/cookie selection must live in oauth::session"
    );
    for marker in [
        "cookies::session_cookie_id_for_secure_transport(headers, secure)",
        "if cookie.is_some() && header.is_some() && cookie != header",
        "cookie.or_else(|| allow_header.then_some(header).flatten())",
    ] {
        assert!(
            OAUTH_SESSION_MODULE.contains(marker),
            "oauth::session must keep the gated selection rule: {marker}"
        );
    }
}

#[test]
fn secure_mode_does_not_accept_local_cookie_names() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("chenxing_session=session; chenxing_csrf=csrf"),
    );

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, true).expect("session cookie parse"),
        None
    );
    assert_eq!(
        csrf_cookie_for_secure_transport(&headers, true).expect("csrf cookie parse"),
        None
    );
    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false)
            .expect("session cookie parse")
            .as_deref(),
        Some("session")
    );
    assert_eq!(
        csrf_cookie_for_secure_transport(&headers, false)
            .expect("csrf cookie parse")
            .as_deref(),
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

#[test]
fn split_cookie_headers_are_all_visible() {
    let mut headers = HeaderMap::new();
    headers.append(
        "cookie",
        HeaderValue::from_static("chenxing_session=session-one"),
    );
    headers.append("cookie", HeaderValue::from_static("chenxing_csrf=csrf-one"));

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false)
            .expect("session cookie parse")
            .as_deref(),
        Some("session-one")
    );
    assert_eq!(
        csrf_cookie_for_secure_transport(&headers, false)
            .expect("csrf cookie parse")
            .as_deref(),
        Some("csrf-one")
    );
}

#[test]
fn duplicate_session_cookie_in_one_header_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("chenxing_session=first; chenxing_session=second"),
    );

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false),
        Err(CookieReadError::Duplicate)
    );
}

#[test]
fn duplicate_session_cookie_across_headers_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.append("cookie", HeaderValue::from_static("chenxing_session=first"));
    headers.append(
        "cookie",
        HeaderValue::from_static("chenxing_csrf=csrf-one; chenxing_session=second"),
    );

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false),
        Err(CookieReadError::Duplicate)
    );
    assert_eq!(
        csrf_cookie_for_secure_transport(&headers, false)
            .expect("csrf cookie parse")
            .as_deref(),
        Some("csrf-one")
    );
}

#[test]
fn invalid_cookie_header_encoding_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.append(
        "cookie",
        HeaderValue::from_bytes(b"chenxing_session=\xff").expect("opaque header"),
    );

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false),
        Err(CookieReadError::Invalid)
    );
}

#[test]
fn invalid_percent_encoding_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert("cookie", HeaderValue::from_static("chenxing_session=%ZZ"));

    assert_eq!(
        session_cookie_id_for_secure_transport(&headers, false),
        Err(CookieReadError::Invalid)
    );
}
