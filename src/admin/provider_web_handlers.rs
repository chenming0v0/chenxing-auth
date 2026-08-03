use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect, Response},
};

/// The custom OAuth provider management page moved into the React admin SPA.
/// Rust only forwards to keep old bookmarks working.
pub async fn oauth_settings(OriginalUri(uri): OriginalUri) -> Response {
    let location = uri.query().filter(|query| !query.is_empty()).map_or_else(
        || "/admin/settings".to_owned(),
        |query| format!("/admin/settings?{query}"),
    );
    Redirect::to(&location).into_response()
}
