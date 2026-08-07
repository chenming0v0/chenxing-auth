use super::super::authorization::MAX_STATE_LENGTH;
use super::*;
use axum::http::{StatusCode, header::LOCATION};

fn client() -> super::super::authorization::RegisteredClient {
    super::super::authorization::RegisteredClient {
        client_id: "client-1".to_owned(),
        client_name: "Test Client".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        owner_user_id: None,
    }
}

fn request(redirect_uri: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: "client-1".to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        response_type: "code".to_owned(),
        scope: "openid".to_owned(),
        state: Some("state-1".to_owned()),
        nonce: None,
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    }
}

#[test]
fn authorization_error_never_redirects_to_unregistered_uri() {
    let response = authorization_error(
        &request("https://attacker.example/callback"),
        &client(),
        AuthorizationRequestError::RedirectUriNotAllowed,
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(LOCATION).is_none());
}

#[test]
fn authorization_error_redirects_only_after_exact_uri_verification() {
    let mut request = request("https://client.example/callback");
    request.response_type = "token".to_owned();
    let response = authorization_error(
        &request,
        &client(),
        AuthorizationRequestError::UnsupportedResponseType,
    );

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("verified redirect location");
    assert!(location.contains("error=unsupported_response_type"));
    assert!(location.contains("state=state-1"));
}

#[test]
fn authorization_error_does_not_reflect_overlong_state() {
    let mut request = request("https://client.example/callback");
    request.state = Some("x".repeat(MAX_STATE_LENGTH + 1));
    let response =
        authorization_error(&request, &client(), AuthorizationRequestError::StateTooLong);

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("verified redirect location");
    assert!(location.contains("error=invalid_request"));
    assert!(!location.contains("state="));
}
