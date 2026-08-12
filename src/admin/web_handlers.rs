use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect, Response},
};

/// `/admin/login` is a legacy URL. The React login page lives at a different
/// path, so GET preserves the query while forwarding to `/login`.
///
/// POST is intentionally not registered: the legacy form-login flow no longer
/// exists (the React page logs in through `/api/v1/auth/login`), and axum
/// answers any unregistered method with `405 Method Not Allowed`. A redirect
/// for POST would be a 303, which silently drops the form body and turns the
/// request into a GET — the failure mode this handler avoids.
pub async fn login_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/login", &uri)
}

fn redirect_to(target: &'static str, uri: &axum::http::Uri) -> Response {
    let location = uri
        .query()
        .filter(|query| !query.is_empty())
        .map_or_else(|| target.to_owned(), |query| format!("{target}?{query}"));
    Redirect::to(&location).into_response()
}
