use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::{
    clients::domain::ClientAuthMethod,
    oauth::client_auth::{
        ClientCredentialError, MAX_CLIENT_ID_LENGTH, MAX_CLIENT_SECRET_LENGTH,
        resolve_client_credentials,
    },
};

#[test]
fn basic_client_authentication_decodes_client_id_and_secret() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Basic Y3hfcHJvamVjdDpjbGllbnQtc2VjcmV0"),
    );

    let credentials = resolve_client_credentials(&headers, None, None).expect("basic credentials");
    assert_eq!(credentials.client_id, "cx_project");
    assert_eq!(credentials.client_secret.as_deref(), Some("client-secret"));
    assert_eq!(credentials.auth_method, ClientAuthMethod::Basic);
}

#[test]
fn basic_authentication_scheme_is_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("basic Y3hfcHJvamVjdDpjbGllbnQtc2VjcmV0"),
    );

    let credentials = resolve_client_credentials(&headers, None, None)
        .expect("case-insensitive basic credentials");
    assert_eq!(credentials.client_id, "cx_project");
}

#[test]
fn form_client_authentication_records_post_method() {
    let credentials =
        resolve_client_credentials(&HeaderMap::new(), Some("cx_project"), Some("client-secret"))
            .expect("form credentials");

    assert_eq!(credentials.auth_method, ClientAuthMethod::Post);
    assert_eq!(credentials.client_secret.as_deref(), Some("client-secret"));
}

#[test]
fn public_client_authentication_records_none_method() {
    let credentials = resolve_client_credentials(&HeaderMap::new(), Some("cx_public"), None)
        .expect("public client credentials");

    assert_eq!(credentials.auth_method, ClientAuthMethod::None);
    assert_eq!(credentials.client_secret, None);
}

#[test]
fn client_authentication_rejects_two_authentication_methods() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Basic Y3hfcHJvamVjdDpjbGllbnQtc2VjcmV0"),
    );

    assert_eq!(
        resolve_client_credentials(&headers, Some("cx_project"), Some("client-secret")),
        Err(ClientCredentialError::MultipleMethods)
    );
}

#[test]
fn client_authentication_rejects_missing_credentials() {
    let headers = HeaderMap::new();
    assert_eq!(
        resolve_client_credentials(&headers, Some(""), Some("")),
        Err(ClientCredentialError::Missing)
    );
}

#[test]
fn client_authentication_rejects_overlong_client_secret() {
    // Issue #353：超长 secret 会把「每请求一次 Argon2」的阻塞池占用线性放大，
    // 必须在解析层直接拒绝，不能流入校验。
    let secret = "x".repeat(MAX_CLIENT_SECRET_LENGTH + 1);
    assert_eq!(
        resolve_client_credentials(&HeaderMap::new(), Some("cx_project"), Some(&secret)),
        Err(ClientCredentialError::TooLong)
    );
}

#[test]
fn basic_authentication_rejects_overlong_client_secret() {
    let secret = "x".repeat(MAX_CLIENT_SECRET_LENGTH + 1);
    let encoded = STANDARD.encode(format!("cx_project:{secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("ascii header value"),
    );
    assert_eq!(
        resolve_client_credentials(&headers, None, None),
        Err(ClientCredentialError::TooLong)
    );
}

#[test]
fn client_authentication_rejects_overlong_client_id() {
    // 超长 client_id 会被原样绑定进 DB 查询，同样在解析层封顶。
    let client_id = "x".repeat(MAX_CLIENT_ID_LENGTH + 1);
    assert_eq!(
        resolve_client_credentials(&HeaderMap::new(), Some(&client_id), None),
        Err(ClientCredentialError::TooLong)
    );
}

#[test]
fn client_authentication_accepts_credentials_at_length_limit() {
    // 恰好等于上限的输入必须放行，上限不能误伤合法凭据。
    let client_id = "x".repeat(MAX_CLIENT_ID_LENGTH);
    let secret = "x".repeat(MAX_CLIENT_SECRET_LENGTH);
    let credentials =
        resolve_client_credentials(&HeaderMap::new(), Some(&client_id), Some(&secret))
            .expect("at-limit credentials");
    assert_eq!(credentials.auth_method, ClientAuthMethod::Post);
}
