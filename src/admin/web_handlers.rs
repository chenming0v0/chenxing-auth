use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect, Response},
};

/// `/admin/login` is a legacy URL. The React login page lives at a different
/// path, so both GET and POST preserve the query while forwarding to `/login`.
pub async fn login_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/login", &uri)
}

pub async fn login_submit(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/login", &uri)
}

fn redirect_to(target: &'static str, uri: &axum::http::Uri) -> Response {
    let location = uri
        .query()
        .filter(|query| !query.is_empty())
        .map_or_else(|| target.to_owned(), |query| format!("{target}?{query}"));
    Redirect::to(&location).into_response()
}
