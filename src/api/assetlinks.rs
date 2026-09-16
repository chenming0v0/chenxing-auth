//! Android App Links 声明端点 `/.well-known/assetlinks.json`。
//!
//! 不经 Issuer 门禁：Android 在 App 安装/更新时抓取该文件校验域名归属，与 OIDC
//! 发行者是否已配置无关；内容只从平台管理（quota_exempt）Client 的声明派生，
//! 不读取任何请求上下文。

use axum::{
    extract::State,
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG},
    },
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::state::AppState;

pub async fn assetlinks(State(state): State<AppState>) -> Response {
    let Ok(links) = state.clients.published_app_links().await else {
        tracing::error!("failed to read app links");
        return crate::error::service_unavailable(
            "assetlinks_unavailable",
            "failed to load Android App Links statements",
        );
    };
    if links.is_empty() {
        return crate::error::not_found(
            "assetlinks_not_configured",
            "no Android App Links statement is published on this issuer",
        );
    };
    let body = serde_json::to_string(
        &links
            .iter()
            .map(|link| {
                serde_json::json!({
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {
                        "namespace": "android_app",
                        "package_name": link.package_name,
                        "sha256_cert_fingerprints": link.sha256_cert_fingerprints,
                    }
                })
            })
            .collect::<Vec<_>>(),
    )
    .expect("serializable");
    let digest = Sha256::digest(body.as_bytes());
    let etag = format!(
        "\"{}\"",
        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            // Android 的抓取器会缓存结果；一小时让指纹轮换在可预期时间内生效。
            (
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600, must-revalidate"),
            ),
            (
                ETAG,
                HeaderValue::from_str(&etag).expect("ETag hex fits header"),
            ),
        ],
        body,
    )
        .into_response()
}
