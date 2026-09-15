//! `/.well-known/assetlinks.json`：Android App Links 声明端点。
//!
//! 辰星域名被移动端 OAuth 客户端用作 HTTPS 回调落地链接，Android 必须能在
//! 该域名下取到列有 App 包名与签名指纹的声明。声明只来自 `ANDROID_ASSETLINKS`，
//! 不经 Issuer 门禁。

use axum::{
    body::Body,
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
};
use chenxing_auth::config::parse_android_assetlinks;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::harness::HarnessBuilder;

const FINGERPRINT: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";

async fn fetch(router: &axum::Router) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/assetlinks.json")
                .body(Body::empty())
                .expect("assetlinks request"),
        )
        .await
        .expect("assetlinks response")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn unconfigured_assetlinks_returns_404_envelope() {
    let harness = HarnessBuilder::new("assetlinks_unconfigured").build().await;
    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert_eq!(body["code"], "assetlinks_not_configured");
    harness.cleanup().await;
}

#[tokio::test]
async fn configured_assetlinks_is_served_without_issuer_gate() {
    let harness = HarnessBuilder::new("assetlinks_configured")
        .configure(|config| {
            // Issuer 缺席时 Android 仍必须能抓取声明：该端点不属于 OIDC 协议面。
            config.issuer = None;
            config.android_assetlinks =
                parse_android_assetlinks(&format!("com.chengming.termux:{FINGERPRINT}"))
                    .expect("valid assetlinks");
        })
        .build()
        .await;
    let response = fetch(&harness.router).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=3600, must-revalidate")
    );
    let body = body_json(response).await;
    assert_eq!(
        body,
        json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.chengming.termux",
                "sha256_cert_fingerprints": [FINGERPRINT],
            }
        }])
    );
    harness.cleanup().await;
}
