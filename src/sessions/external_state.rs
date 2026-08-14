//! External OAuth state Cookie.
//!
//! Production (`COOKIE_SECURE=true`) uses a dynamic `__Host-` name so the
//! browser itself rejects Domain-scoped cookies from a same-site sibling.
//! `COOKIE_SECURE=false` is a named loopback-only branch: the unprefixed
//! name is never consulted when `secure` is true.

use crate::sessions::cookies::{self, CookieError};
use axum::http::{HeaderMap, header::SET_COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Loopback HTTP name prefix. Production must not read or write this name.
pub const EXTERNAL_STATE_COOKIE_PREFIX: &str = "chenxing_external_oauth_state_";
/// Production host-only name prefix. `__Host-` requires Secure, Path=/, no Domain.
pub const HOST_EXTERNAL_STATE_COOKIE_PREFIX: &str = "__Host-chenxing_external_oauth_state_";
const EXTERNAL_STATE_COOKIE_ID_BYTES: usize = 12;

pub fn external_state_cookie_prefix(secure: bool) -> &'static str {
    if secure {
        HOST_EXTERNAL_STATE_COOKIE_PREFIX
    } else {
        EXTERNAL_STATE_COOKIE_PREFIX
    }
}

pub fn external_state_cookie_name(state: &str, secure: bool) -> String {
    let digest = Sha256::digest(state.as_bytes());
    format!(
        "{}{}",
        external_state_cookie_prefix(secure),
        URL_SAFE_NO_PAD.encode(&digest[..EXTERNAL_STATE_COOKIE_ID_BYTES])
    )
}

pub fn append_external_state_cookie(
    headers: &mut HeaderMap,
    state: &str,
    max_age_seconds: u64,
    secure: bool,
) -> Result<(), CookieError> {
    let name = external_state_cookie_name(state, secure);
    headers.append(
        SET_COOKIE,
        cookies::build_cookie(&name, state, max_age_seconds, secure, true, "/")?,
    );
    Ok(())
}

pub fn append_clear_external_state_cookie(
    headers: &mut HeaderMap,
    state: &str,
    secure: bool,
) -> Result<(), CookieError> {
    let name = external_state_cookie_name(state, secure);
    headers.append(
        SET_COOKIE,
        cookies::build_cookie(&name, "", 0, secure, true, "/")?,
    );
    Ok(())
}

/// Read the transport-selected host-only state Cookie.
///
/// Production only accepts the `__Host-` name. A parent-domain cookie that
/// reused the loopback prefix is a different name and cannot satisfy this
/// lookup. Conflicting duplicates of the selected name fail closed.
pub fn external_state(headers: &HeaderMap, state: &str, secure: bool) -> Option<String> {
    cookies::unique_cookie_value(headers, &external_state_cookie_name(state, secure))
}
