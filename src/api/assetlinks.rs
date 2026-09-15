//! Android App Links 声明端点 `/.well-known/assetlinks.json`。
//!
//! 不经 Issuer 门禁：Android 在 App 安装/更新时抓取该文件校验域名归属，与 OIDC
//! 发行者是否已配置无关；内容只来自静态配置，不读取任何请求上下文。

use axum::{
    extract::State,
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};

use crate::state::AppState;

pub async fn assetlinks(State(state): State<AppState>) -> Response {
    let Some(links) = state.config.android_assetlinks.as_ref() else {
        return crate::error::not_found(
            "assetlinks_not_configured",
            "no Android App Links statement is published on this issuer",
        );
    };
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            // Android 的抓取器会缓存结果；一小时让指纹轮换在可预期时间内生效。
            (
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600, must-revalidate"),
            ),
        ],
        links.to_json(),
    )
        .into_response()
}
