use super::{authorization::current_admin_permission, domain::AdminPermission};
use crate::{state::AppState, web};
use axum::{
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
pub async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    Html(web::page(
        "管理后台",
        "<main><h1>辰星认证中枢管理后台</h1><p>请使用管理 API 执行具体操作。</p></main>",
    ))
    .into_response()
}
pub async fn login_page() -> Response {
    Redirect::to("/auth/login").into_response()
}
pub async fn login_submit() -> Response {
    Redirect::to("/auth/login").into_response()
}
pub async fn protected_placeholder(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    Html(web::page(
        "管理后台",
        "<main><h1>管理后台</h1><p>请使用对应的 JSON 管理接口。</p></main>",
    ))
    .into_response()
}
