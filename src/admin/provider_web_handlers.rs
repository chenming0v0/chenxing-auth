use axum::response::{IntoResponse, Redirect, Response};

/// The custom OAuth provider management page moved into the React SPA console
/// (`/console/settings`). Rust only forwards to keep old bookmarks working.
pub async fn oauth_settings() -> Response {
    Redirect::to("/console/settings").into_response()
}
