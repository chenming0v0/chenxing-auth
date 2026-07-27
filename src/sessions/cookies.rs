use axum::http::{
    HeaderMap,
    header::{COOKIE, SET_COOKIE},
};
use cookie::{Cookie, SameSite};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "chenxing_session";
pub const CSRF_COOKIE: &str = "chenxing_csrf";

pub fn append_login_cookies(
    headers: &mut HeaderMap,
    session_id: Uuid,
    csrf_token: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    headers.append(
        SET_COOKIE,
        build_cookie(
            SESSION_COOKIE,
            &session_id.to_string(),
            max_age_seconds,
            secure,
            true,
        )
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

pub fn session_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-chenxing-session")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .or_else(|| {
            cookie_value(headers, SESSION_COOKIE).and_then(|value| Uuid::parse_str(&value).ok())
        })
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
