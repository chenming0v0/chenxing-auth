use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect, Response},
};

/// All `/admin/*` pages now live in the React SPA. Rust only forwards so the
/// legacy bookmarks and automation keep working while the UI renders in React.
pub async fn dashboard(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/admin", &uri)
}

pub async fn login_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/login", &uri)
}

pub async fn login_submit(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/login", &uri)
}

pub async fn users_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/admin/users", &uri)
}

pub async fn clients_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/admin/clients", &uri)
}

pub async fn audit_page(OriginalUri(uri): OriginalUri) -> Response {
    redirect_to("/admin/audit", &uri)
}

fn redirect_to(target: &'static str, uri: &axum::http::Uri) -> Response {
    let location = uri
        .query()
        .filter(|query| !query.is_empty())
        .map_or_else(|| target.to_owned(), |query| format!("{target}?{query}"));
    Redirect::to(&location).into_response()
}
