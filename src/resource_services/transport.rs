//! Account Provider v1 出网传输边界。
//!
//! 高层客户端只依赖窄接口 [`ProviderTransport`]，后续状态机测试可以注入 fake
//! provider；生产实现 [`ReqwestProviderTransport::production`] **恒用**生产网络
//! 策略：HTTPS、公网 DNS 筛查、禁用代理、禁止重定向、2s 连接 / 5s 总超时。不存在
//! 允许私网或明文 HTTP 的环境开关。

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::oauth::providers::endpoint_policy::{
    EndpointPolicy, PublicEndpointResolver, validate_endpoint_url,
};

// 响应上限与解析入口共用同一个常量，避免两处数字漂移。
pub use super::scalar::MAX_RESPONSE_BYTES;
use super::secret::SecretString;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
/// `Retry-After` 的接受上界；超出的值一律钳制，避免被远端拖住。
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// 一次出网请求。`authorization` 是已构造好的完整头值，`Debug` 会脱敏。
pub struct ProviderHttpRequest {
    pub method: HttpMethod,
    pub url: Url,
    pub authorization: Option<SecretString>,
    pub idempotency_key: Option<Uuid>,
    pub body: Vec<u8>,
}

impl fmt::Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("authorization", &self.authorization)
            .field("idempotency_key", &self.idempotency_key)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// 一次出网响应。`retry_after_seconds` 由传输层解析并钳制；`body` 不进入 `Debug`。
#[derive(Clone)]
pub struct ProviderHttpResponse {
    pub status: u16,
    pub retry_after_seconds: Option<u64>,
    pub body: Vec<u8>,
}

impl fmt::Debug for ProviderHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpResponse")
            .field("status", &self.status)
            .field("retry_after_seconds", &self.retry_after_seconds)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// 传输失败。不携带 URL、地址或底层 reqwest 错误文本。
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    #[error("account provider request timed out")]
    Timeout,
    #[error("account provider endpoint was rejected by the outbound policy")]
    EndpointRejected,
    #[error("account provider is unavailable")]
    Unavailable,
    #[error("account provider response exceeds the 128 KiB limit")]
    ResponseTooLarge,
}

/// 窄异步传输接口的返回 future。用类型别名避免 trait 签名触发复杂度告警。
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, TransportError>> + Send + 'a>>;

/// 窄异步传输接口。返回 boxed future 以保持 trait 可对象化，且不引入 `async-trait`。
pub trait ProviderTransport: Send + Sync {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a>;
}

/// 生产网络实现。构造路径上没有任何放宽选项。
pub struct ReqwestProviderTransport {
    client: Client,
}

impl ReqwestProviderTransport {
    pub fn production() -> Result<Self, TransportError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .dns_resolver(Arc::new(PublicEndpointResolver::new(
                EndpointPolicy::PRODUCTION,
            )))
            .build()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(Self { client })
    }
}

impl ProviderTransport for ReqwestProviderTransport {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            // 每次建连前再判一次地址边界：URL 即使被调用方篡改也必须过生产策略。
            validate_endpoint_url(&request.url, EndpointPolicy::PRODUCTION)
                .map_err(|_| TransportError::EndpointRejected)?;
            let mut builder = match request.method {
                HttpMethod::Get => self.client.get(request.url),
                HttpMethod::Post => self.client.post(request.url),
            };
            if let Some(key) = request.idempotency_key {
                builder = builder.header("Idempotency-Key", key.to_string());
            }
            if request.method == HttpMethod::Post {
                builder = builder
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(request.body);
            }
            let mut built = builder.build().map_err(|_| TransportError::Unavailable)?;
            if let Some(authorization) = &request.authorization {
                apply_authorization(&mut built, authorization.expose())?;
            }
            let response = self
                .client
                .execute(built)
                .await
                .map_err(map_request_error)?;
            let status = response.status().as_u16();
            let retry_after_seconds = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(clamp_retry_after_seconds);
            let body = read_limited(response).await?;
            Ok(ProviderHttpResponse {
                status,
                retry_after_seconds,
                body,
            })
        })
    }
}

/// 钳制 `Retry-After` 到可接受上界。
pub fn clamp_retry_after_seconds(seconds: u64) -> u64 {
    seconds.min(MAX_RETRY_AFTER_SECONDS)
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_request_error)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn map_request_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else {
        TransportError::Unavailable
    }
}

/// 把授权头以 `sensitive` 方式写入已构建请求。
///
/// reqwest 的 `RequestBuilder::header()` 不接受已经构造好的 `HeaderValue`，会把
/// sensitive 重置为 false；因此先在 `build()` 后直接操作 `HeaderMap`。抽成独立函数
/// 是为了让单元测试能直接验证该标志确实生效。
fn apply_authorization(
    request: &mut reqwest::Request,
    authorization: &str,
) -> Result<(), TransportError> {
    let mut value = reqwest::header::HeaderValue::from_str(authorization)
        .map_err(|_| TransportError::Unavailable)?;
    value.set_sensitive(true);
    request
        .headers_mut()
        .insert(reqwest::header::AUTHORIZATION, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_header_is_marked_sensitive() {
        let mut request = Client::new()
            .get("https://provider.example.com/")
            .build()
            .expect("request");
        apply_authorization(&mut request, "Bearer secret-token").expect("apply");

        let header = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .expect("authorization header");
        assert!(header.is_sensitive());
        assert_eq!(header.to_str().expect("ascii"), "Bearer secret-token");
        // sensitive 标志必须让 Debug 脱敏。
        assert!(!format!("{header:?}").contains("secret-token"));
    }
}
