use axum::http::{HeaderMap, HeaderValue};
use chenxing_auth::oauth::client_auth::{ClientCredentialError, resolve_client_credentials};

#[test]
fn basic_client_authentication_decodes_client_id_and_secret() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Basic Y3hfcHJvamVjdDpjbGllbnQtc2VjcmV0"),
    );

    let credentials =
        resolve_client_credentials(&headers, Some(""), Some("")).expect("basic credentials");
    assert_eq!(credentials.client_id, "cx_project");
    assert_eq!(credentials.client_secret, "client-secret");
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
