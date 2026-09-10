//! Outbound CLtermux HTTP boundary.

use std::time::Duration;

use reqwest::{Client, StatusCode, header};
use uuid::Uuid;

use super::{
    contract::{AccountSnapshotDto, VerifyRequest},
    types::{CredentialBundle, IntegrationError},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct CltermuxClient {
    base_url: url::Url,
    outbound_token: String,
    http: Client,
}

impl CltermuxClient {
    pub fn new(config: &crate::config::CltermuxConfig) -> Result<Self, IntegrationError> {
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(std::sync::Arc::new(
                crate::oauth::providers::endpoint_policy::PublicEndpointResolver::new(
                    crate::oauth::providers::endpoint_policy::EndpointPolicy::PRODUCTION,
                ),
            ))
            .build()
            .map_err(|_| IntegrationError::ProviderUnavailable)?;
        Ok(Self {
            base_url: config.base_url.clone(),
            outbound_token: config.outbound_token.clone(),
            http,
        })
    }

    pub async fn verify(
        &self,
        credentials: CredentialBundle,
    ) -> Result<AccountSnapshotDto, IntegrationError> {
        let request = VerifyRequest {
            public_key: credentials.public_key.clone(),
            private_key: credentials.private_key.clone(),
        };
        self.post_json("api/v1/integrations/chenxing/bindings/verify", &request)
            .await
    }

    pub async fn lookup(&self, uid: &str) -> Result<AccountSnapshotDto, IntegrationError> {
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "api/v1/integrations/chenxing/accounts/{}",
            urlencoding_segment(uid)
        ));
        self.send(self.http.get(url)).await
    }

    async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<AccountSnapshotDto, IntegrationError> {
        let body =
            serde_json::to_vec(body).map_err(|_| IntegrationError::ProviderInvalidResponse)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(IntegrationError::ProviderInvalidResponse);
        }
        let url = self.endpoint(path);
        self.send(
            self.http
                .post(url)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await
    }

    fn endpoint(&self, path: &str) -> url::Url {
        let mut url = self.base_url.clone();
        url.set_path(path);
        url
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<AccountSnapshotDto, IntegrationError> {
        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let response = request
            .bearer_auth(&self.outbound_token)
            .header("X-Request-ID", request_id)
            .send()
            .await
            .map_err(map_request_error)?;
        let status = response.status();
        let bytes = read_limited(response).await?;
        if !status.is_success() {
            return Err(map_status(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ProviderInvalidResponse)
    }
}

fn urlencoding_segment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, IntegrationError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_request_error)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(IntegrationError::ProviderInvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn map_request_error(error: reqwest::Error) -> IntegrationError {
    if error.is_timeout() {
        IntegrationError::ProviderTimeout
    } else {
        IntegrationError::ProviderUnavailable
    }
}

fn map_status(status: StatusCode, _body: &[u8]) -> IntegrationError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => IntegrationError::ProviderAuthFailed,
        StatusCode::NOT_FOUND => IntegrationError::AccountNotFound,
        StatusCode::TOO_MANY_REQUESTS => IntegrationError::RateLimited {
            retry_after_secs: 30,
        },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            IntegrationError::InvalidCredential
        }
        _ if status.is_server_error() => IntegrationError::ProviderUnavailable,
        _ => IntegrationError::ProviderInvalidResponse,
    }
}
