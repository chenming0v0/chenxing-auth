use chenxing_auth::oauth::authorization::{
    AuthorizationRequest, AuthorizationRequestError, RegisteredClient,
    validate_authorization_request,
};

fn client() -> RegisteredClient {
    RegisteredClient {
        client_id: "cx_project".to_owned(),
        redirect_uris: vec!["https://project.example/callback".to_owned()],
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
    }
}

#[test]
fn authorization_request_accepts_exact_redirect_and_pkce() {
    let request = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid profile".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: Some("nonce-value".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect("valid authorization request");

    assert_eq!(request.scopes, vec!["openid", "profile"]);
    assert_eq!(request.nonce.as_deref(), Some("nonce-value"));
}

#[test]
fn authorization_request_rejects_missing_state() {
    let error = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect_err("state is required");

    assert_eq!(error, AuthorizationRequestError::MissingState);
}

#[test]
fn authorization_request_rejects_scope_outside_client_registration() {
    let error = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "email".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: None,
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect_err("unregistered scope must be rejected");

    assert_eq!(error, AuthorizationRequestError::ScopeNotAllowed);
}

#[test]
fn authorization_request_rejects_blank_nonce() {
    let error = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: Some("  ".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect("nonce is optional when omitted, but blank nonce is normalized away");

    assert_eq!(error.nonce, None);
}
