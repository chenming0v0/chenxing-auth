use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use crate::sessions::cookies;

/// Resolve the pending-login proof from browser cookies. The optional request
/// field is retained only for clients that still send the old JSON shape; it is
/// a constant-time consistency check and never replaces either cookie proof.
/// Missing cookies, mismatched values, and legacy unbound Redis tickets fail
/// closed so a leaked ticket cannot be replayed from another browser.
pub(super) fn ticket_proof(
    headers: &HeaderMap,
    supplied_ticket: Option<&str>,
    secure: bool,
) -> Option<(String, String)> {
    let ticket_id = cookies::login_ticket_id_for_secure_transport(headers, secure)?;
    let holder = cookies::login_ticket_holder_for_secure_transport(headers, secure)?;
    if let Some(supplied_ticket) = supplied_ticket {
        let matches: bool = ticket_id
            .as_bytes()
            .ct_eq(supplied_ticket.as_bytes())
            .into();
        if !matches {
            return None;
        }
    }
    Some((ticket_id, cookies::login_ticket_holder_hash(&holder)))
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header::COOKIE};

    use super::ticket_proof;
    use crate::sessions::cookies;

    fn pending_headers(ticket_id: &str, holder: &str) -> HeaderMap {
        let mut response_headers = HeaderMap::new();
        cookies::append_login_ticket_cookies(
            &mut response_headers,
            ticket_id,
            holder,
            300,
            false,
        );
        let cookie_header = response_headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value))
            .collect::<Vec<_>>()
            .join("; ");
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&cookie_header).expect("cookie header"),
        );
        headers
    }

    #[test]
    fn proof_requires_both_pending_cookies() {
        let headers = pending_headers("ticket-1", "holder-1");
        assert!(ticket_proof(&headers, None, false).is_some());

        let mut missing_holder = HeaderMap::new();
        missing_holder.insert(
            COOKIE,
            HeaderValue::from_static("chenxing_login_ticket=ticket-1"),
        );
        assert!(ticket_proof(&missing_holder, None, false).is_none());
    }

    #[test]
    fn legacy_request_field_is_only_a_matching_consistency_check() {
        let headers = pending_headers("ticket-1", "holder-1");
        assert!(ticket_proof(&headers, Some("ticket-1"), false).is_some());
        assert!(ticket_proof(&headers, Some("stolen-ticket"), false).is_none());
    }
}
