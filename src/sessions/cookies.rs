use axum::http::{
    HeaderMap,
    header::{COOKIE, SET_COOKIE},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// Secure browser session cookie. The `__Host-` prefix requires Secure, Path=/,
/// and no Domain attribute, which makes the host-only contract browser-enforced.
pub const SESSION_COOKIE: &str = "__Host-chenxing_session";
/// Secure browser CSRF cookie. See [`SESSION_COOKIE`] for the prefix contract.
pub const CSRF_COOKIE: &str = "__Host-chenxing_csrf";
const LOCAL_SESSION_COOKIE: &str = "chenxing_session";
const LOCAL_CSRF_COOKIE: &str = "chenxing_csrf";
pub const EXTERNAL_STATE_COOKIE_PREFIX: &str = "chenxing_external_oauth_state_";
const EXTERNAL_STATE_COOKIE_ID_BYTES: usize = 12;
/// 授权请求持有者 Cookie：证明调用绑定端点的浏览器就是发起 `/oauth/authorize`
/// 的那一个（#115）。只在服务端与 pending 记录中的摘要比对，值本身不进日志。
pub const AUTHZ_HOLDER_COOKIE: &str = "chenxing_authz_holder";
const AUTHZ_HOLDER_BYTES: usize = 32;
/// Pending login ticket cookie. The ticket is HttpOnly so normal browser code
/// cannot copy the bearer value into a URL, log, or response body.
pub const LOGIN_TICKET_COOKIE: &str = "__Host-chenxing_login_ticket";
/// Separate browser holder proof for a pending login ticket. Redis stores only
/// its digest, so a leaked ticket value alone cannot complete MFA.
pub const LOGIN_TICKET_HOLDER_COOKIE: &str = "__Host-chenxing_login_holder";
const LOCAL_LOGIN_TICKET_COOKIE: &str = "chenxing_login_ticket";
const LOCAL_LOGIN_TICKET_HOLDER_COOKIE: &str = "chenxing_login_holder";
const LOGIN_TICKET_HOLDER_BYTES: usize = 32;

pub fn append_login_cookies(
    headers: &mut HeaderMap,
    session_token: &str,
    csrf_token: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    let session_name = session_cookie_name(secure);
    let csrf_name = csrf_cookie_name(secure);
    headers.append(
        SET_COOKIE,
        build_cookie(
            session_name,
            session_token,
            max_age_seconds,
            secure,
            true,
            "/",
        )
        .parse()
        .expect("session cookie is valid ASCII"),
    );
    headers.append(
        SET_COOKIE,
        build_cookie(csrf_name, csrf_token, max_age_seconds, secure, false, "/")
            .parse()
            .expect("CSRF cookie is valid ASCII"),
    );
}

pub fn append_clear_cookies(headers: &mut HeaderMap, secure: bool) {
    let session_name = session_cookie_name(secure);
    let csrf_name = csrf_cookie_name(secure);
    for name in [session_name, csrf_name] {
        headers.append(
            SET_COOKIE,
            build_cookie(name, "", 0, secure, name == session_name, "/")
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
    path: &str,
) {
    let name = external_state_cookie_name(state);
    headers.append(
        SET_COOKIE,
        build_cookie(&name, state, max_age_seconds, secure, true, path)
            .parse()
            .expect("external OAuth state cookie is valid ASCII"),
    );
}

pub fn append_clear_external_state_cookie(
    headers: &mut HeaderMap,
    state: &str,
    secure: bool,
    path: &str,
) {
    let name = external_state_cookie_name(state);
    headers.append(
        SET_COOKIE,
        build_cookie(&name, "", 0, secure, true, path)
            .parse()
            .expect("external OAuth state cookie is valid ASCII"),
    );
}

/// 生成一个随机的授权持有者值（32 字节，base64url 编码，不含填充）。
/// 该值只通过 HttpOnly Cookie 下发，不写入日志或 pending 记录。
pub fn new_authz_holder() -> String {
    let mut bytes = [0_u8; AUTHZ_HOLDER_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 计算 holder 值的 SHA-256 摘要（base64url 无填充），用于存入 pending 记录。
/// 只暴露摘要，原值不离开调用方。
pub fn authz_holder_hash(holder: &str) -> String {
    let digest = Sha256::digest(holder.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn new_login_ticket_holder() -> String {
    let mut bytes = [0_u8; LOGIN_TICKET_HOLDER_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn login_ticket_holder_hash(holder: &str) -> String {
    let digest = Sha256::digest(holder.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn append_login_ticket_cookies(
    headers: &mut HeaderMap,
    ticket_id: &str,
    holder: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    let ticket_name = login_ticket_cookie_name(secure);
    let holder_name = login_ticket_holder_cookie_name(secure);
    for (name, value) in [(ticket_name, ticket_id), (holder_name, holder)] {
        headers.append(
            SET_COOKIE,
            build_cookie(name, value, max_age_seconds, secure, true, "/")
                .parse()
                .expect("login ticket cookie is valid ASCII"),
        );
    }
}

pub fn append_clear_login_ticket_cookies(headers: &mut HeaderMap, secure: bool) {
    let ticket_name = login_ticket_cookie_name(secure);
    let holder_name = login_ticket_holder_cookie_name(secure);
    for name in [ticket_name, holder_name] {
        headers.append(
            SET_COOKIE,
            build_cookie(name, "", 0, secure, true, "/")
                .parse()
                .expect("clear login ticket cookie is valid ASCII"),
        );
    }
}

pub fn login_ticket_id_for_secure_transport(
    headers: &HeaderMap,
    secure: bool,
) -> Option<String> {
    cookie_value(headers, login_ticket_cookie_name(secure))
}

pub fn login_ticket_holder_for_secure_transport(
    headers: &HeaderMap,
    secure: bool,
) -> Option<String> {
    cookie_value(headers, login_ticket_holder_cookie_name(secure))
}

/// 下发授权请求持有者 Cookie（HttpOnly, SameSite=Lax, path="/"）。
///
/// 路径设 `/` 而非 `/oauth/`：bind 端点位于 `/api/v1/...`，受限路径会导致
/// bind 调用收不到此 Cookie。HttpOnly 阻止脚本读取，Lax 允许从外部 IdP
/// 跳回时携带（top-level cross-site GET 携带 Lax Cookie）。
pub fn append_authz_holder_cookie(
    headers: &mut HeaderMap,
    holder: &str,
    max_age_seconds: u64,
    secure: bool,
) {
    headers.append(
        SET_COOKIE,
        build_cookie(
            AUTHZ_HOLDER_COOKIE,
            holder,
            max_age_seconds,
            secure,
            true, // http_only
            "/",
        )
        .parse()
        .expect("authz holder cookie is valid ASCII"),
    );
}

/// 从请求 Cookie 头中提取授权持有者值（如存在）。
pub fn extract_authz_holder_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, AUTHZ_HOLDER_COOKIE)
}

pub fn session_id(headers: &HeaderMap) -> Option<String> {
    session_header_id(headers).or_else(|| session_cookie_id(headers))
}

pub fn session_header_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-chenxing-session")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub fn session_cookie_id(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, SESSION_COOKIE)
}

pub fn session_cookie_id_for_secure_transport(headers: &HeaderMap, secure: bool) -> Option<String> {
    cookie_value(headers, session_cookie_name(secure))
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

pub fn csrf_cookie_for_secure_transport(headers: &HeaderMap, secure: bool) -> Option<String> {
    cookie_value(headers, csrf_cookie_name(secure))
}

pub const fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        SESSION_COOKIE
    } else {
        LOCAL_SESSION_COOKIE
    }
}

pub const fn csrf_cookie_name(secure: bool) -> &'static str {
    if secure {
        CSRF_COOKIE
    } else {
        LOCAL_CSRF_COOKIE
    }
}

pub const fn login_ticket_cookie_name(secure: bool) -> &'static str {
    if secure {
        LOGIN_TICKET_COOKIE
    } else {
        LOCAL_LOGIN_TICKET_COOKIE
    }
}

pub const fn login_ticket_holder_cookie_name(secure: bool) -> &'static str {
    if secure {
        LOGIN_TICKET_HOLDER_COOKIE
    } else {
        LOCAL_LOGIN_TICKET_HOLDER_COOKIE
    }
}

pub fn external_state(headers: &HeaderMap, state: &str) -> Option<String> {
    let name = external_state_cookie_name(state);
    cookie_value(headers, &name)
}

pub fn external_state_cookie_name(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());
    format!(
        "{EXTERNAL_STATE_COOKIE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&digest[..EXTERNAL_STATE_COOKIE_ID_BYTES])
    )
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
        build_cookie(
            session_name,
            session_token,
            max_age_seconds,
            secure,
            true,
            "/",
        )
        .parse()
        .expect("session cookie is valid ASCII"),
    );
    headers.append(
        SET_COOKIE,
        build_cookie(csrf_name, csrf_token, max_age_seconds, secure, false, "/")
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
            build_cookie(name, "", 0, secure, name == session_name, "/")
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
    path: &str,
) -> String {
    let mut cookie = Cookie::build((name, value))
        .path(path)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            max_age_seconds.min(i64::MAX as u64) as i64,
        ));
    if secure || name.starts_with("__Host-") {
        cookie = cookie.secure(true);
    }
    if http_only {
        cookie = cookie.http_only(true);
    }
    cookie.build().to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        authz_holder_hash, login_ticket_holder_hash, new_authz_holder, new_login_ticket_holder,
    };

    /// 回归 #115：holder 值生成应足够随机且长度合理。
    #[test]
    fn authz_holder_is_random_and_sufficiently_long() {
        let holder1 = new_authz_holder();
        let holder2 = new_authz_holder();
        assert_ne!(holder1, holder2, "consecutive holders must differ");
        assert!(
            holder1.len() > 40,
            "base64url(32 bytes) should be ~43 chars, got {}",
            holder1.len()
        );
    }

    /// 回归 #115：holder 哈希计算应稳定且不可逆。
    #[test]
    fn authz_holder_hash_is_stable() {
        let holder = "test_holder_value";
        let hash1 = authz_holder_hash(holder);
        let hash2 = authz_holder_hash(holder);
        assert_eq!(hash1, hash2, "same input must produce same hash");
        assert_ne!(hash1, holder, "hash must not be the original holder value");
        assert!(
            hash1.len() > 40,
            "base64url(SHA-256) should be ~43 chars, got {}",
            hash1.len()
        );
    }

    /// 回归 #115：不同的 holder 值产生不同的哈希。
    #[test]
    fn different_holders_produce_different_hashes() {
        let hash1 = authz_holder_hash("holder_a");
        let hash2 = authz_holder_hash("holder_b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn login_ticket_holder_is_random_and_hashed() {
        let holder1 = new_login_ticket_holder();
        let holder2 = new_login_ticket_holder();
        assert_ne!(holder1, holder2);
        assert_ne!(login_ticket_holder_hash(&holder1), holder1);
        assert_ne!(
            login_ticket_holder_hash(&holder1),
            login_ticket_holder_hash(&holder2)
        );
    }
}
