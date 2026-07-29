use axum::http::{
    HeaderMap,
    header::{COOKIE, SET_COOKIE},
};
use cookie::{Cookie, SameSite};

pub const SESSION_COOKIE: &str = "chenxing_session";
pub const CSRF_COOKIE: &str = "chenxing_csrf";
pub const EXTERNAL_STATE_COOKIE: &str = "chenxing_external_oauth_state";

pub fn append_login_cookies(
    headers: &mut HeaderMap,
    session_token: &str,
    csrf_token: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    headers.append(
        SET_COOKIE,
        build_cookie(SESSION_COOKIE, session_token, max_age_seconds, secure, true)
            .parse()
            .expect("session cookie is valid ASCII"),
    );
    headers.append(
        SET_COOKIE,
        build_cookie(CSRF_COOKIE, csrf_token, max_age_seconds, secure, false)
            .parse()
            .expect("CSRF cookie is valid ASCII"),
    );
}

pub fn append_clear_cookies(headers: &mut HeaderMap, secure: bool) {
    for name in [SESSION_COOKIE, CSRF_COOKIE] {
        headers.append(
            SET_COOKIE,
            build_cookie(name, "", 0, secure, name == SESSION_COOKIE)
                .parse()
                .expect("clear cookie is valid ASCII"),
        );
    }
}

pub fn append_external_state_cookie(
    headers: &mut HeaderMap,
    state: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    headers.append(
        SET_COOKIE,
        build_cookie(EXTERNAL_STATE_COOKIE, state, max_age_seconds, secure, true)
            .parse()
            .expect("external OAuth state cookie is valid ASCII"),
    );
}

pub fn append_clear_external_state_cookie(headers: &mut HeaderMap, secure: bool) {
    headers.append(
        SET_COOKIE,
        build_cookie(EXTERNAL_STATE_COOKIE, "", 0, secure, true)
            .parse()
            .expect("external OAuth state cookie is valid ASCII"),
    );
}

pub fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-chenxing-session")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| cookie_value(headers, SESSION_COOKIE))
}

pub fn csrf_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub fn csrf_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, CSRF_COOKIE)
}

pub fn external_state(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, EXTERNAL_STATE_COOKIE)
}

pub fn cookie_value_by_name(headers: &HeaderMap, name: &str) -> Option<String> {
    cookie_value(headers, name)
}

pub fn append_named_login_cookies(
    headers: &mut HeaderMap,
    session_name: &str,
    csrf_name: &str,
    session_token: &str,
    csrf_token: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    headers.append(
        SET_COOKIE,
        build_cookie(session_name, session_token, max_age_seconds, secure, true)
            .parse()
            .expect("session cookie is valid ASCII"),
    );
    headers.append(
        SET_COOKIE,
        build_cookie(csrf_name, csrf_token, max_age_seconds, secure, false)
            .parse()
            .expect("CSRF cookie is valid ASCII"),
    );
}

pub fn append_named_clear_cookies(
    headers: &mut HeaderMap,
    session_name: &str,
    csrf_name: &str,
    secure: bool,
) {
    for name in [session_name, csrf_name] {
        headers.append(
            SET_COOKIE,
            build_cookie(name, "", 0, secure, name == session_name)
                .parse()
                .expect("clear cookie is valid ASCII"),
        );
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|part| {
        let cookie = Cookie::parse(part.trim()).ok()?;
        (cookie.name() == name).then(|| cookie.value().to_owned())
    })
}

fn build_cookie(
    name: &str,
    value: &str,
    max_age_seconds: u64,
    secure: bool,
    http_only: bool,
) -> String {
    let mut cookie = Cookie::build((name, value))
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            max_age_seconds.min(i64::MAX as u64) as i64,
        ));
    if secure {
        cookie = cookie.secure(true);
    }
    if http_only {
        cookie = cookie.http_only(true);
    }
    cookie.build().to_string()
}
