//! 客户端固定路径、认证分离、错误映射与不重试语义的测试。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;

use super::bundle::AccessToken;
use super::client::{
    ACCOUNT_PATH, AccountProviderClient, LINK_SESSIONS_PATH, METADATA_PATH, REFRESH_PATH,
    REVOKE_PATH,
};
use super::error::{ClientError, KnownErrorCode, ProtocolError};
use super::fixtures;
use super::request::{
    CreateLinkSessionRequest, RefreshLinkSessionRequest, RevokeLinkSessionRequest,
};
use super::scalar::Issuer;
use super::secret::SecretString;
use super::transport::{
    MAX_RESPONSE_BYTES, ProviderHttpRequest, ProviderHttpResponse, ProviderTransport,
    TransportFuture, clamp_retry_after_seconds,
};
use super::{RefreshBinding, UtcTime};

const BINDING: &str = "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f";
const GRANT: &str = "9f0c2b7e-3d41-4a88-b1c2-7e6f5d4c3b2a";

struct FakeTransport {
    responses: Mutex<VecDeque<ProviderHttpResponse>>,
    requests: Mutex<Vec<ProviderHttpRequest>>,
}

impl FakeTransport {
    fn with_responses(responses: Vec<ProviderHttpResponse>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn take_requests(&self) -> Vec<ProviderHttpRequest> {
        std::mem::take(&mut *self.requests.lock().expect("requests"))
    }
}

impl ProviderTransport for FakeTransport {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        self.requests.lock().expect("requests").push(request);
        let response = self
            .responses
            .lock()
            .expect("responses")
            .pop_front()
            .unwrap_or(ProviderHttpResponse {
                status: 500,
                retry_after_seconds: None,
                body: Vec::new(),
            });
        Box::pin(async move { Ok(response) })
    }
}

fn issuer() -> Issuer {
    Issuer::parse("https://provider.example.com").expect("issuer")
}

fn make_client(
    responses: Vec<ProviderHttpResponse>,
) -> (AccountProviderClient<FakeTransport>, Arc<FakeTransport>) {
    let transport = FakeTransport::with_responses(responses);
    let client = AccountProviderClient::new(
        transport.clone(),
        issuer(),
        "portal-client",
        SecretString::new("portal-secret"),
    )
    .expect("client");
    (client, transport)
}

fn response(status: u16, body: &str) -> ProviderHttpResponse {
    ProviderHttpResponse {
        status,
        retry_after_seconds: None,
        body: body.as_bytes().to_vec(),
    }
}

fn create_request() -> CreateLinkSessionRequest {
    CreateLinkSessionRequest::new(
        Uuid::parse_str(BINDING).expect("uuid"),
        "pub-example-0001",
        "priv-example-0001",
    )
    .expect("request")
}

#[tokio::test]
async fn create_uses_the_fixed_path_basic_auth_and_the_supplied_key() {
    let (client, transport) = make_client(vec![response(201, fixtures::LINK_SESSION_RESPONSE)]);
    let key = Uuid::new_v4();
    client
        .create_link_session(key, &create_request())
        .await
        .expect("create");
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, super::transport::HttpMethod::Post);
    assert_eq!(requests[0].url.path(), LINK_SESSIONS_PATH);
    assert_eq!(requests[0].idempotency_key, Some(key));
    let authorization = requests[0]
        .authorization
        .as_ref()
        .expect("authorization")
        .expose();
    assert!(authorization.starts_with("Basic "));
    assert!(!format!("{:?}", requests[0]).contains("portal-secret"));
}

#[tokio::test]
async fn create_never_retries_even_when_a_retryable_status_is_returned() {
    let (client, transport) = make_client(vec![
        ProviderHttpResponse {
            status: 503,
            retry_after_seconds: Some(10),
            body: br#"{"error":{"code":"provider_unavailable"}}"#.to_vec(),
        },
        response(201, fixtures::LINK_SESSION_RESPONSE),
    ]);
    let error = client
        .create_link_session(Uuid::new_v4(), &create_request())
        .await
        .expect_err("create must not retry");
    assert_eq!(
        error.provider_failure().map(|failure| failure.code),
        Some(KnownErrorCode::ProviderUnavailable)
    );
    assert_eq!(transport.take_requests().len(), 1);
}

#[tokio::test]
async fn refresh_reuses_the_caller_key_and_enforces_grant_identity() {
    let (client, transport) = make_client(vec![response(200, fixtures::REFRESH_RESPONSE)]);
    let key = Uuid::new_v4();
    let token =
        super::RefreshToken::parse("cxap_rt_AgICAgICAgICAgICAgICAgICAgICAgICAgICA").expect("token");
    let request = RefreshLinkSessionRequest::new(Uuid::parse_str(BINDING).expect("uuid"), token);
    let binding = RefreshBinding {
        grant_id: Uuid::parse_str(GRANT).expect("grant"),
        uid: "acct-1001",
        grant_expires_at: UtcTime::parse_rfc3339("2026-12-17T00:00:00Z").expect("time"),
    };
    client
        .refresh_link_session(key, &request, &binding)
        .await
        .expect("refresh");
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), REFRESH_PATH);
    assert_eq!(requests[0].idempotency_key, Some(key));
    assert!(
        requests[0]
            .authorization
            .as_ref()
            .expect("authorization")
            .expose()
            .starts_with("Basic ")
    );
}

#[tokio::test]
async fn account_uses_bearer_and_checks_the_expected_uid() {
    let (client, transport) = make_client(vec![response(200, fixtures::ACCOUNT_SNAPSHOT)]);
    let token = AccessToken::parse("cxap_at_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        .expect("access token");
    let snapshot = client.account(&token, "acct-1001").await.expect("account");
    assert_eq!(snapshot.uid, "acct-1001");
    let requests = transport.take_requests();
    assert_eq!(requests[0].url.path(), ACCOUNT_PATH);
    let authorization = requests[0].authorization.as_ref().expect("authorization");
    assert!(authorization.expose().starts_with("Bearer "));
    assert!(!format!("{authorization:?}").contains("cxap_at_"));
}

#[tokio::test]
async fn account_rejects_a_mismatched_expected_uid() {
    let (client, _) = make_client(vec![response(200, fixtures::ACCOUNT_SNAPSHOT)]);
    let token = AccessToken::parse("cxap_at_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        .expect("access token");
    assert!(matches!(
        client
            .account(&token, "acct-9999")
            .await
            .expect_err("uid mismatch"),
        ClientError::InvalidResponse(ProtocolError::UidMismatch)
    ));
}

#[tokio::test]
async fn revoke_accepts_an_optional_idempotency_key() {
    let (client, transport) = make_client(vec![ProviderHttpResponse {
        status: 204,
        retry_after_seconds: None,
        body: Vec::new(),
    }]);
    let request = RevokeLinkSessionRequest::new(Uuid::parse_str(BINDING).expect("uuid"));
    client
        .revoke_link_session(Some(Uuid::new_v4()), &request)
        .await
        .expect("revoke");
    let requests = transport.take_requests();
    assert_eq!(requests[0].url.path(), REVOKE_PATH);
    assert!(requests[0].idempotency_key.is_some());
}

#[tokio::test]
async fn metadata_uses_the_fixed_path_and_must_match_the_configured_issuer() {
    let (client, transport) = make_client(vec![response(200, fixtures::METADATA)]);
    let metadata = client.metadata().await.expect("metadata");
    assert_eq!(metadata.issuer.as_str(), "https://provider.example.com");
    assert_eq!(transport.take_requests()[0].url.path(), METADATA_PATH);

    let mut mismatched = fixtures::value(fixtures::METADATA);
    mismatched["issuer"] = serde_json::json!("https://other.example.com");
    let (client, _) = make_client(vec![response(200, &mismatched.to_string())]);
    assert!(matches!(
        client.metadata().await.expect_err("issuer mismatch"),
        ClientError::InvalidResponse(ProtocolError::IssuerMismatch)
    ));
}

#[tokio::test]
async fn known_error_codes_and_retry_after_are_preserved_without_messages() {
    let envelope = fixtures::ERROR_ENVELOPE;
    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 422,
        retry_after_seconds: None,
        body: envelope.as_bytes().to_vec(),
    }]);
    let error = client
        .create_link_session(Uuid::new_v4(), &create_request())
        .await
        .expect_err("credential invalid");
    let failure = error.provider_failure().expect("provider failure");
    assert_eq!(failure.code, KnownErrorCode::CredentialInvalid);
    assert!(!failure.retryable());
    // 对方 message 不得出现在错误里。
    assert!(!format!("{error:?}").contains("credentials rejected"));

    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 429,
        retry_after_seconds: Some(30),
        body: br#"{"error":{"code":"rate_limited","message":"slow down"}}"#.to_vec(),
    }]);
    let error = client
        .create_link_session(Uuid::new_v4(), &create_request())
        .await
        .expect_err("rate limited");
    let failure = error.provider_failure().expect("provider failure");
    assert!(failure.retryable());
    assert_eq!(failure.retry_after, Some(Duration::from_secs(30)));
    assert!(!format!("{error:?}").contains("slow down"));
}

#[tokio::test]
async fn error_code_must_match_the_http_status() {
    // 502 + invalid_refresh_token 只是坏网关，不能被当成凭据失效的证据。
    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 502,
        retry_after_seconds: None,
        body: br#"{"error":{"code":"invalid_refresh_token"}}"#.to_vec(),
    }]);
    assert!(matches!(
        client
            .create_link_session(Uuid::new_v4(), &create_request())
            .await
            .expect_err("status/code mismatch"),
        ClientError::UnexpectedStatus(502)
    ));

    // 状态与错误码自洽时正常映射。
    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 409,
        retry_after_seconds: None,
        body: br#"{"error":{"code":"refresh_already_committed"}}"#.to_vec(),
    }]);
    let failure = client
        .create_link_session(Uuid::new_v4(), &create_request())
        .await
        .expect_err("409")
        .provider_failure()
        .expect("provider failure");
    assert_eq!(failure.code, KnownErrorCode::RefreshAlreadyCommitted);
}

#[tokio::test]
async fn unknown_error_codes_and_wrong_success_statuses_fail_closed() {
    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 418,
        retry_after_seconds: None,
        body: br#"{"error":{"code":"teapot"}}"#.to_vec(),
    }]);
    assert!(matches!(
        client
            .create_link_session(Uuid::new_v4(), &create_request())
            .await
            .expect_err("unknown code"),
        ClientError::UnexpectedStatus(418)
    ));

    let (client, _) = make_client(vec![response(200, fixtures::LINK_SESSION_RESPONSE)]);
    assert!(matches!(
        client
            .create_link_session(Uuid::new_v4(), &create_request())
            .await
            .expect_err("wrong success status"),
        ClientError::UnexpectedStatus(200)
    ));
}

#[tokio::test]
async fn oversized_responses_and_retry_after_clamping_are_bounded() {
    let body = vec![b'x'; MAX_RESPONSE_BYTES + 1];
    let (client, _) = make_client(vec![ProviderHttpResponse {
        status: 200,
        retry_after_seconds: None,
        body,
    }]);
    assert!(matches!(
        client.metadata().await.expect_err("too large"),
        ClientError::ResponseTooLarge
    ));
    assert_eq!(clamp_retry_after_seconds(7200), 3600);
    assert_eq!(clamp_retry_after_seconds(5), 5);
}

#[tokio::test]
async fn invalid_response_bodies_are_rejected_as_protocol_errors() {
    let (client, _) = make_client(vec![response(200, "not json")]);
    assert!(matches!(
        client.metadata().await.expect_err("malformed"),
        ClientError::InvalidResponse(ProtocolError::MalformedJson)
    ));
}
