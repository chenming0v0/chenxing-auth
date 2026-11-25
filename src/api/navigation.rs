//! 首次部署的文档导航门禁，仅作用于 React 页面入口。

use axum::{
    extract::{Request as AxumRequest, State},
    http::header::ACCEPT,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use crate::state::AppState;

/// 在文档导航边界处理首次部署重定向，避免 SPA 每次挂载都探测隐藏的引导接口。
pub(super) async fn bootstrap_navigation_guard(
    State(state): State<AppState>,
    request: AxumRequest,
    next: Next,
) -> Response {
    if !is_document_navigation(&request) {
        return next.run(request).await;
    }
    let path = request.uri().path();
    if !is_spa_navigation_path(path) {
        return next.run(request).await;
    }

    let initialized = match state.users.owner_initialized().await {
        Ok(initialized) => initialized,
        Err(error_value) => {
            tracing::warn!(
                error = %error_value,
                event = "bootstrap.navigation_state_unavailable",
                "continuing with the SPA shell because bootstrap navigation state is unavailable"
            );
            return next.run(request).await;
        }
    };

    if let Some(target) = navigation_target(path, initialized) {
        return Redirect::temporary(target).into_response();
    }
    next.run(request).await
}

fn is_document_navigation(request: &AxumRequest) -> bool {
    if !matches!(
        request.method(),
        &axum::http::Method::GET | &axum::http::Method::HEAD
    ) {
        return false;
    }
    if !is_spa_navigation_path(request.uri().path()) {
        return false;
    }
    let accepts_html = request
        .headers()
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        });
    if !accepts_html {
        return false;
    }
    request
        .headers()
        .get("sec-fetch-dest")
        .is_none_or(|value| value.as_bytes() == b"document")
}

fn navigation_target(path: &str, initialized: bool) -> Option<&'static str> {
    if !is_spa_navigation_path(path) {
        return None;
    }
    if initialized {
        (path == "/bootstrap").then_some("/login")
    } else {
        (path != "/bootstrap").then_some("/bootstrap")
    }
}

fn is_spa_navigation_path(path: &str) -> bool {
    if path.contains('%')
        || path.starts_with("/assets/")
        || path == "/api"
        || path.starts_with("/api/")
        || path == "/auth/external"
        || path.starts_with("/auth/external/")
        || path == "/health"
        || path.starts_with("/health/")
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.split('/').any(|segment| segment.starts_with('.'))
        || has_file_extension(path)
    {
        return false;
    }
    if path == "/oauth" || path.starts_with("/oauth/") {
        return matches!(
            path,
            "/oauth/account" | "/oauth/consent" | "/oauth/redirect"
        );
    }
    true
}

fn has_file_extension(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment
            .rsplit_once('.')
            .is_some_and(|(_, extension)| !extension.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    fn document_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("accept", "text/html,application/xhtml+xml")
            .header("sec-fetch-dest", "document")
            .body(Body::empty())
            .expect("document request")
    }

    #[test]
    fn document_navigation_requires_html_accept_and_document_fetch_metadata() {
        assert!(is_document_navigation(&document_request("/login")));

        let api_request = Request::builder()
            .method("GET")
            .uri("/api/v1/auth/me")
            .header("accept", "application/json")
            .body(Body::empty())
            .expect("api request");
        assert!(!is_document_navigation(&api_request));

        let asset_request = document_request("/assets/index-ABC12345.js");
        assert!(!is_document_navigation(&asset_request));

        let non_document_fetch = Request::builder()
            .method("GET")
            .uri("/login")
            .header("accept", "text/html")
            .header("sec-fetch-dest", "empty")
            .body(Body::empty())
            .expect("fetch request");
        assert!(!is_document_navigation(&non_document_fetch));
    }

    #[test]
    fn bootstrap_navigation_target_preserves_first_light_and_ready_routes() {
        assert_eq!(navigation_target("/login", false), Some("/bootstrap"));
        assert_eq!(navigation_target("/console", false), Some("/bootstrap"));
        assert_eq!(navigation_target("/bootstrap", false), None);
        assert_eq!(navigation_target("/bootstrap", true), Some("/login"));
        assert_eq!(navigation_target("/login", true), None);
        assert_eq!(navigation_target("/api/v1/auth/me", false), None);
        assert_eq!(navigation_target("/assets/index-ABC12345.js", false), None);
        assert_eq!(navigation_target("/oauth/authorize", false), None);
        assert_eq!(
            navigation_target("/oauth/account", false),
            Some("/bootstrap")
        );
    }
}
