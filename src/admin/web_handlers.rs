use axum::response::{IntoResponse, Redirect, Response};

/// All `/admin/*` pages now live in the React SPA. Rust only forwards so the
/// legacy bookmarks and automation keep working while the UI renders in React.
pub async fn dashboard() -> Response {
    redirect_to("/console")
}

pub async fn login_page() -> Response {
    redirect_to("/auth/login")
}

pub async fn login_submit() -> Response {
    redirect_to("/auth/login")
}

pub async fn users_page() -> Response {
    redirect_to("/console/users")
}

pub async fn clients_page() -> Response {
    redirect_to("/console/developer")
}

pub async fn audit_page() -> Response {
    redirect_to("/console/overview")
}

fn redirect_to(target: &'static str) -> Response {
    Redirect::to(target).into_response()
}
