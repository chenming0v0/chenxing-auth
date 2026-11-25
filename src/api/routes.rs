//! 按业务职责组装应用路由；Issuer 和请求超时仍由 api::router 在整表外统一包裹。

use axum::Router;

use crate::state::AppState;

mod account;
mod clients;
mod management;
mod oauth;
mod settings;

pub(super) fn register(router: Router<AppState>) -> Router<AppState> {
    let router = crate::resource_services::routes::register(router);
    let router = oauth::register(router);
    let router = account::register(router);
    let router = management::register(router);
    let router = settings::register(router);
    clients::register(router)
}
