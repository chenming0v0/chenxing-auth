//! OIDC 发现文档与 JWKS 端点。

use axum::{
    Json,
    extract::State,
    http::{
        HeaderMap,
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN, VARY},
    },
    response::{IntoResponse, Response},
};

use crate::{error, oauth::OpenIdConfiguration, state::AppState};

/// Discovery 文档。
///
/// Issuer 取自配置而非请求 Host：`APP_ISSUER` 是 OIDC 发行者标识，
/// 从反向代理输入推导会让攻击者能改写发行者。
pub(super) async fn openid_configuration(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let mut response = Json(OpenIdConfiguration::for_issuer_with_scopes(
        &state.config.issuer_url,
        &state.config.client_registration_limits.allowed_scopes,
    ))
    .into_response();
    // Discovery 是公开的只读元数据，允许任意来源读取；
    // 带上 Vary 以免缓存把有/无 Origin 的响应混用。
    if headers.contains_key(ORIGIN) {
        response.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            axum::http::HeaderValue::from_static("*"),
        );
        response
            .headers_mut()
            .insert(VARY, axum::http::HeaderValue::from_static("Origin"));
    }
    response
}

/// JWKS 只返回公钥部分，私钥材料不得出现在任何 API 响应中。
pub(super) async fn jwks(State(state): State<AppState>) -> Response {
    match state.keys.fresh_jwks() {
        Ok(jwks) => Json(jwks).into_response(),
        Err(key_error) => {
            tracing::error!(error = %key_error, "failed to refresh signing keys for JWKS");
            error::internal()
        }
    }
}
