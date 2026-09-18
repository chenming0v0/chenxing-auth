//! Account Provider v1 消费方 HTTP 客户端。
//!
//! 端点路径是编译期常量，**不**接受元数据或调用方提供的任意 URL。认证严格分离：
//! Basic 只用于创建 / 刷新 / 撤销，Bearer 只用于账号查询。成功状态码必须精确匹配
//! （创建 201、刷新与查询 200、撤销 204）；错误信封只保留协议已知错误码与受限的
//! `Retry-After`，对方 `message`、凭据与令牌都不落日志、不进错误。

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use super::bundle::{AccessToken, RefreshBinding, TokenBundle};
use super::error::{ClientError, KnownErrorCode, ProtocolError, ProviderFailure};
use super::metadata::ProviderMetadata;
use super::request::{
    CreateLinkSessionRequest, RefreshLinkSessionRequest, RevokeLinkSessionRequest,
};
use super::scalar::Issuer;
use super::secret::SecretString;
use super::snapshot::AccountSnapshot;
use super::transport::{
    HttpMethod, MAX_RESPONSE_BYTES, ProviderHttpRequest, ProviderHttpResponse, ProviderTransport,
    ReqwestProviderTransport,
};

pub const METADATA_PATH: &str = "/.well-known/account-provider";
pub const LINK_SESSIONS_PATH: &str = "/api/v1/account-provider/link-sessions";
pub const REFRESH_PATH: &str = "/api/v1/account-provider/link-sessions/refresh";
pub const ACCOUNT_PATH: &str = "/api/v1/account-provider/account";
pub const REVOKE_PATH: &str = "/api/v1/account-provider/link-sessions/revoke";

pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 512;

/// 绑定到单个提供方 issuer 的客户端。传输实现可注入，便于用 fake provider 测试。
pub struct AccountProviderClient<T: ProviderTransport + ?Sized> {
    transport: Arc<T>,
    issuer: Issuer,
    client_id: String,
    client_secret: SecretString,
}

impl<T: ProviderTransport + ?Sized> AccountProviderClient<T> {
    pub fn new(
        transport: Arc<T>,
        issuer: Issuer,
        client_id: impl Into<String>,
        client_secret: SecretString,
    ) -> Result<Self, ProtocolError> {
        let client_id = client_id.into();
        // RFC 7617 的 Basic 用户名为 client_id，冒号是分隔符，不允许出现在其中。
        if client_id.is_empty() || client_id.len() > MAX_CLIENT_ID_BYTES || client_id.contains(':')
        {
            return Err(ProtocolError::InvalidClientId);
        }
        Ok(Self {
            transport,
            issuer,
            client_id,
            client_secret,
        })
    }

    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// 公开元数据。issuer 必须与配置 origin 严格一致（按 origin 比较，规避尾斜杠）。
    pub async fn metadata(&self) -> Result<ProviderMetadata, ClientError> {
        let response = self
            .send(ProviderHttpRequest {
                method: HttpMethod::Get,
                url: self.endpoint(METADATA_PATH),
                authorization: None,
                idempotency_key: None,
                body: Vec::new(),
            })
            .await?;
        let body = expect_status(response, 200)?;
        let metadata = ProviderMetadata::parse(&body)?;
        if metadata.issuer.as_str() != self.issuer.as_str() {
            return Err(ClientError::InvalidResponse(ProtocolError::IssuerMismatch));
        }
        Ok(metadata)
    }

    /// 创建绑定。调用方负责生成并持久化 `client_binding_id`；本方法不自动重试。
    pub async fn create_link_session(
        &self,
        idempotency_key: Uuid,
        request: &CreateLinkSessionRequest,
    ) -> Result<TokenBundle, ClientError> {
        let value = serde_json::json!({
            "client_binding_id": request.client_binding_id().to_string(),
            "credentials": {
                "identifier": request.credentials().identifier().expose(),
                "secret": request.credentials().secret().expose(),
            },
        });
        let body = self.basic_authorization();
        let response = self
            .send(ProviderHttpRequest {
                method: HttpMethod::Post,
                url: self.endpoint(LINK_SESSIONS_PATH),
                authorization: Some(body),
                idempotency_key: Some(idempotency_key),
                body: encode_body(value)?,
            })
            .await?;
        let bytes = expect_status(response, 201)?;
        let bundle = TokenBundle::parse(&bytes)?;
        bundle.validate_create(&self.issuer, request.client_binding_id())?;
        Ok(bundle)
    }

    /// 刷新绑定。`idempotency_key` 由上层持久化的操作决定；客户端不擅自换 key，
    /// 也不在内部重试（歧义重试由上层用同 key + 同 refresh_token 发起）。
    pub async fn refresh_link_session(
        &self,
        idempotency_key: Uuid,
        request: &RefreshLinkSessionRequest,
        binding: &RefreshBinding<'_>,
    ) -> Result<TokenBundle, ClientError> {
        let value = serde_json::json!({
            "client_binding_id": request.client_binding_id().to_string(),
            "refresh_token": request.refresh_token().expose(),
        });
        let authorization = self.basic_authorization();
        let response = self
            .send(ProviderHttpRequest {
                method: HttpMethod::Post,
                url: self.endpoint(REFRESH_PATH),
                authorization: Some(authorization),
                idempotency_key: Some(idempotency_key),
                body: encode_body(value)?,
            })
            .await?;
        let bytes = expect_status(response, 200)?;
        let bundle = TokenBundle::parse(&bytes)?;
        bundle.validate_refresh(&self.issuer, request.client_binding_id(), binding)?;
        Ok(bundle)
    }

    /// 读取令牌所绑定账号的快照。无 uid 参数，但快照 uid 必须等于调用方本地
    /// 已持久化的预期 uid：强制调用方显式绑定，避免漏掉这项校验。
    pub async fn account(
        &self,
        access_token: &AccessToken,
        expected_uid: &str,
    ) -> Result<AccountSnapshot, ClientError> {
        let response = self
            .send(ProviderHttpRequest {
                method: HttpMethod::Get,
                url: self.endpoint(ACCOUNT_PATH),
                authorization: Some(SecretString::new(format!(
                    "Bearer {}",
                    access_token.expose()
                ))),
                idempotency_key: None,
                body: Vec::new(),
            })
            .await?;
        let body = expect_status(response, 200)?;
        let snapshot = AccountSnapshot::parse(&body)?;
        if snapshot.issuer.as_str() != self.issuer.as_str() {
            return Err(ClientError::InvalidResponse(ProtocolError::IssuerMismatch));
        }
        if snapshot.uid != expected_uid {
            return Err(ClientError::InvalidResponse(ProtocolError::UidMismatch));
        }
        Ok(snapshot)
    }

    /// 撤销绑定（幂等 204）。`idempotency_key` 可选：丢失创建响应后的清理路径应传入
    /// 一个**新的** key 再对同一 binding 发撤销。
    pub async fn revoke_link_session(
        &self,
        idempotency_key: Option<Uuid>,
        request: &RevokeLinkSessionRequest,
    ) -> Result<(), ClientError> {
        let value = serde_json::json!({
            "client_binding_id": request.client_binding_id().to_string(),
        });
        let authorization = self.basic_authorization();
        let response = self
            .send(ProviderHttpRequest {
                method: HttpMethod::Post,
                url: self.endpoint(REVOKE_PATH),
                authorization: Some(authorization),
                idempotency_key,
                body: encode_body(value)?,
            })
            .await?;
        expect_status(response, 204)?;
        Ok(())
    }

    async fn send(
        &self,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpResponse, ClientError> {
        self.transport
            .execute(request)
            .await
            .map_err(ClientError::from)
    }

    fn endpoint(&self, path: &'static str) -> Url {
        let mut url = self.issuer.as_url().clone();
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    fn basic_authorization(&self) -> SecretString {
        let raw = format!("{}:{}", self.client_id, self.client_secret.expose());
        SecretString::new(format!("Basic {}", STANDARD.encode(raw.as_bytes())))
    }
}

impl AccountProviderClient<ReqwestProviderTransport> {
    /// 生产构造：始终使用生产网络策略，没有任何 `allow_private` / `insecure` 开关。
    pub fn production(
        issuer: Issuer,
        client_id: impl Into<String>,
        client_secret: SecretString,
    ) -> Result<Self, ClientError> {
        let transport = ReqwestProviderTransport::production().map_err(ClientError::Transport)?;
        Self::new(Arc::new(transport), issuer, client_id, client_secret)
            .map_err(ClientError::InvalidResponse)
    }
}

fn encode_body(value: serde_json::Value) -> Result<Vec<u8>, ClientError> {
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| ClientError::InvalidResponse(ProtocolError::MalformedJson))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::InvalidResponse(ProtocolError::RequestTooLarge));
    }
    Ok(bytes)
}

fn expect_status(response: ProviderHttpResponse, expected: u16) -> Result<Vec<u8>, ClientError> {
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError::ResponseTooLarge);
    }
    if response.status == expected {
        return Ok(response.body);
    }
    if (200..300).contains(&response.status) {
        return Err(ClientError::UnexpectedStatus(response.status));
    }
    match parse_error_code(&response.body, response.status) {
        Some(code) => Err(ClientError::Provider(ProviderFailure {
            code,
            retry_after: response.retry_after_seconds.map(Duration::from_secs),
        })),
        None => Err(ClientError::UnexpectedStatus(response.status)),
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
}

/// 只读取 `error.code`；`message`、`retryable`、`request_id` 一律丢弃。
///
/// 返回的已知错误码必须与 HTTP 状态自洽（协议 §10），否则调用方按
/// [`ClientError::UnexpectedStatus`] 处理：例如 `502 + invalid_refresh_token`
/// 只是坏网关，不能据此让上层销毁仍然有效的授权。
fn parse_error_code(body: &[u8], status: u16) -> Option<KnownErrorCode> {
    let envelope: ErrorEnvelope = serde_json::from_slice(body).ok()?;
    let code = KnownErrorCode::parse(&envelope.error.code)?;
    (code.expected_status() == status).then_some(code)
}
