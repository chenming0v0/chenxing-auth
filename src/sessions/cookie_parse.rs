use axum::http::{HeaderMap, header::COOKIE};
use cookie::Cookie;
use thiserror::Error;

/// Failure while reading a security-sensitive Cookie.
///
/// This is the shared parse boundary for session, CSRF, login ticket/holder,
/// authz holder, external OAuth state, and any future caller that already
/// computed a cookie name (including dynamic `__Host-` names). Callers must
/// not pick the first of several values: both variants mean "this request has
/// no usable cookie" and map onto the existing reject path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CookieReadError {
    /// A `Cookie` header is not valid HTTP string encoding, a field cannot be
    /// parsed, or a value has illegal percent-encoding.
    ///
    /// Values are treated as opaque strings here. Callers that later decode
    /// base64url (session tokens, holders, state) already fail closed without
    /// panicking; this layer refuses undecodable headers so we never skip a
    /// header that might contain another copy of the same name.
    #[error("cookie header is malformed")]
    Invalid,
    /// The same cookie name appeared more than once across the request.
    #[error("duplicate security cookie")]
    Duplicate,
}

/// Walk every `Cookie` header and every `name=value` field.
///
/// - Missing name → `Ok(None)`
/// - Exactly one well-formed value → `Ok(Some)`
/// - Duplicate name, undecodable header, malformed field, or illegal
///   percent-encoding → `Err`
///
/// Name matching is exact. Transport-specific prefixes (`__Host-` vs local)
/// stay at the caller so a later dynamic `__Host-` state cookie reuses this
/// function unchanged.
pub fn read_named_cookie(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, CookieReadError> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let header = header.to_str().map_err(|_| CookieReadError::Invalid)?;
        for part in header.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let cookie = Cookie::parse(part).map_err(|_| CookieReadError::Invalid)?;
            if cookie.name() != name {
                continue;
            }
            let value = cookie.value();
            if !has_valid_percent_encoding(value.as_bytes()) {
                return Err(CookieReadError::Invalid);
            }
            if found.replace(value.to_owned()).is_some() {
                return Err(CookieReadError::Duplicate);
            }
        }
    }
    Ok(found)
}

/// `percent_decode` keeps incomplete or non-hex `%` sequences as-is, so a
/// later base64url decode can panic-free-fail on garbage or, worse, accept a
/// different token than the browser stored. Reject those sequences here.
fn has_valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= value.len()
            || !value[index + 1].is_ascii_hexdigit()
            || !value[index + 2].is_ascii_hexdigit()
        {
            return false;
        }
        index += 3;
    }
    true
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header::COOKIE};

    use super::{CookieReadError, read_named_cookie};

    fn headers_from(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                COOKIE,
                HeaderValue::from_str(value).expect("valid cookie header"),
            );
        }
        headers
    }

    #[test]
    fn single_header_returns_the_named_value() {
        let headers = headers_from(&["chenxing_session=session-one; chenxing_csrf=csrf-one"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session")
                .unwrap()
                .as_deref(),
            Some("session-one")
        );
        assert_eq!(
            read_named_cookie(&headers, "chenxing_csrf")
                .unwrap()
                .as_deref(),
            Some("csrf-one")
        );
        assert_eq!(
            read_named_cookie(&headers, "chenxing_login_ticket").unwrap(),
            None
        );
    }

    #[test]
    fn split_across_headers_returns_each_name() {
        let headers = headers_from(&["chenxing_session=session-one", "chenxing_csrf=csrf-one"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session")
                .unwrap()
                .as_deref(),
            Some("session-one")
        );
        assert_eq!(
            read_named_cookie(&headers, "chenxing_csrf")
                .unwrap()
                .as_deref(),
            Some("csrf-one")
        );
    }

    #[test]
    fn duplicate_name_in_the_same_header_is_rejected() {
        let headers = headers_from(&["chenxing_session=first; chenxing_session=second"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Duplicate)
        );
    }

    #[test]
    fn duplicate_name_across_headers_is_rejected() {
        let headers = headers_from(&[
            "chenxing_session=first",
            "chenxing_csrf=csrf-one; chenxing_session=second",
        ]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Duplicate)
        );
        assert_eq!(
            read_named_cookie(&headers, "chenxing_csrf")
                .unwrap()
                .as_deref(),
            Some("csrf-one")
        );
    }

    #[test]
    fn identical_duplicate_values_are_still_rejected() {
        let headers = headers_from(&["chenxing_session=same", "chenxing_session=same"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Duplicate)
        );
    }

    #[test]
    fn invalid_header_encoding_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_bytes(b"chenxing_session=\xff").expect("opaque header"),
        );
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Invalid)
        );
    }

    #[test]
    fn invalid_percent_encoding_is_rejected() {
        let headers = headers_from(&["chenxing_session=%ZZ"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Invalid)
        );
        let headers = headers_from(&["chenxing_session=%"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Invalid)
        );
    }

    #[test]
    fn opaque_base64_values_do_not_panic() {
        let headers = headers_from(&["chenxing_session=abc+def/=="]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session")
                .expect("standard base64 is an opaque cookie value")
                .as_deref(),
            Some("abc+def/==")
        );
    }

    #[test]
    fn malformed_field_is_rejected_without_taking_a_later_value() {
        let headers = headers_from(&["=missing-name; chenxing_session=session-one"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session"),
            Err(CookieReadError::Invalid)
        );
    }

    #[test]
    fn trailing_semicolon_is_not_a_malformed_field() {
        let headers = headers_from(&["chenxing_session=session-one;"]);
        assert_eq!(
            read_named_cookie(&headers, "chenxing_session")
                .unwrap()
                .as_deref(),
            Some("session-one")
        );
    }
}
