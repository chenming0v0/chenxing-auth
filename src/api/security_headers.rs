use axum::{
    http::{HeaderMap, HeaderName, HeaderValue},
    response::Response,
};

const FRAME_ANCESTORS_POLICY: &str = "frame-ancestors 'none'";
const HSTS_POLICY: &str = "max-age=31536000; includeSubDomains";

pub(super) fn hsts_enabled(issuer_url: &str) -> bool {
    url::Url::parse(issuer_url).is_ok_and(|issuer| issuer.scheme() == "https")
}

pub(super) async fn apply(response: Response, hsts_enabled: bool) -> Response {
    let mut response = response;
    let headers = response.headers_mut();
    set_header(headers, "x-frame-options", "DENY");
    set_header(headers, "content-security-policy", FRAME_ANCESTORS_POLICY);
    set_header(headers, "x-content-type-options", "nosniff");
    set_header(headers, "referrer-policy", "no-referrer");
    if hsts_enabled {
        set_header(headers, "strict-transport-security", HSTS_POLICY);
    }
    response
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, response::Response};

    use super::{apply, hsts_enabled};

    #[test]
    fn hsts_follows_the_configured_issuer_scheme() {
        assert!(!hsts_enabled("http://127.0.0.1:3000"));
        assert!(hsts_enabled("https://auth.example.com"));
    }

    #[tokio::test]
    async fn http_responses_get_baseline_headers_without_hsts() {
        let response = apply(Response::new(Body::empty()), false).await;

        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["content-security-policy"],
            "frame-ancestors 'none'"
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response
                .headers()
                .get("strict-transport-security")
                .is_none()
        );
    }

    #[tokio::test]
    async fn https_responses_get_hsts() {
        let response = apply(Response::new(Body::empty()), true).await;

        assert_eq!(
            response.headers()["strict-transport-security"],
            "max-age=31536000; includeSubDomains"
        );
    }
}
