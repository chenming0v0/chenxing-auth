//! OIDC 发现文档与 JWKS 端点。

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, ORIGIN,
            VARY,
        },
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::{api::extract::RequestIssuer, oauth::OpenIdConfiguration, state::AppState};

/// 公开只读元数据端点的 CORS：允许任意来源读取，不带凭据。
///
/// Discovery 和 JWKS 都是公开的只读元数据，任何 RP 都需要跨域拉取。
/// `Access-Control-Allow-Origin: *` 只与不带凭据的请求兼容——这两个端点不读取
/// Cookie 或 Authorization，因此 `*` 是安全的。
///
/// `Vary: Origin` **始终**写出：响应是否携带 ACAO 取决于请求是否带 Origin。
/// 若只在带 Origin 的变体上写 Vary，共享缓存可能把「无 Origin、无 ACAO」的副本
/// 直接交给跨域 RP，浏览器会因缺少 CORS 头拒绝读取。
fn apply_public_cors(request_headers: &HeaderMap, response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(VARY, HeaderValue::from_static("Origin"));
    if request_headers.contains_key(ORIGIN) {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    }
}

/// JWKS 缓存策略：公开缓存 60 秒，过期后必须重新验证。
///
/// `must-revalidate` 阻止缓存在回源失败时返回陈旧 JWKS——陈旧公钥会让新签发的
/// 令牌验签失败。60 秒远短于密钥保留窗口（默认 7 天），轮换后最迟 60 秒全网
/// 看到新公钥；同时足够长，能挡住 RP 对 JWKS 的高频轮询。
const JWKS_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// 为 JWKS 响应体计算确定性 ETag（RFC 7232 强 ETag）。
///
/// 对序列化后的 JWKS 字节做 SHA-256 再 base64url 编码，包裹在双引号内。
/// 同一公钥集合始终产出同一 ETag；密钥轮换或吊销改变公钥集合后 ETag 随之改变。
/// 不依赖内存指针或时间戳，跨实例一致。
fn jwks_etag(body: &[u8]) -> HeaderValue {
    let digest = Sha256::digest(body);
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    match HeaderValue::from_str(&format!("\"{encoded}\"")) {
        Ok(value) => value,
        Err(_) => HeaderValue::from_static("\"jwks\""),
    }
}

/// 检查 `If-None-Match` 是否匹配给定 ETag（RFC 7232 §3.2）。
///
/// `*` 匹配任何资源；否则按逗号分隔逐个比较，比较的是完整 ETag（含引号）。
fn if_none_match_matches(request_headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Some(client_value) = request_headers.get(IF_NONE_MATCH) else {
        return false;
    };
    let Ok(client_str) = client_value.to_str() else {
        return false;
    };
    if client_str.trim() == "*" {
        return true;
    }
    let target = etag.to_str().unwrap_or("");
    client_str
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == target)
}

/// Discovery 文档。
///
/// Issuer 取自配置而非请求 Host：`APP_ISSUER` 是 OIDC 发行者标识，
/// 从反向代理输入推导会让攻击者能改写发行者。
pub(super) async fn openid_configuration(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
) -> Response {
    let mut response = Json(OpenIdConfiguration::for_issuer_with_scopes(
        issuer.issuer().as_str(),
        &state.config.client_registration_limits.allowed_scopes,
    ))
    .into_response();
    apply_public_cors(&headers, &mut response);
    response
}

/// JWKS 只返回公钥部分，私钥材料不得出现在任何 API 响应中。
///
/// 直接返回内存快照：JWKS 是被 RP 高频轮询的公开端点，在这里同步读密钥目录
/// 会让并发请求互相抢目录锁并各自失败（Issue #257）。与共享目录的一致性由
/// `KeyManager::run_disk_sync_worker` 的后台任务负责。
///
/// 缓存：`Cache-Control: public, max-age=60, must-revalidate` + 确定性 ETag。
/// RP 在 `max-age` 内可直接用共享缓存；过期后用 `If-None-Match` 条件请求，
/// 公钥集合未变则返回 304，避免重复传输完整 JWKS。
pub(super) async fn jwks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let body = match serde_json::to_vec(&state.keys.jwks()) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize JWKS");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let etag = jwks_etag(&body);

    if if_none_match_matches(&headers, &etag) {
        let mut response = (StatusCode::NOT_MODIFIED, Body::empty()).into_response();
        let response_headers = response.headers_mut();
        response_headers.insert(ETAG, etag);
        response_headers.insert(CACHE_CONTROL, HeaderValue::from_static(JWKS_CACHE_CONTROL));
        apply_public_cors(&headers, &mut response);
        return response;
    }

    let mut response = Response::new(Body::from(body));
    let response_headers = response.headers_mut();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static(JWKS_CACHE_CONTROL));
    response_headers.insert(ETAG, etag);
    apply_public_cors(&headers, &mut response);
    response
}
