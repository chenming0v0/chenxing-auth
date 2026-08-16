use super::super::authorization::MAX_STATE_LENGTH;
use super::*;
use axum::http::{StatusCode, header::LOCATION};

const UI_HANDLERS_SOURCE: &str = include_str!("ui_handlers.rs");

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

fn pending(redirect_uri: &str) -> PendingAuthorization {
    PendingAuthorization {
        request_id: "request-1".to_owned(),
        client_id: "client-1".to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        scope: "openid".to_owned(),
        state: "state-1".to_owned(),
        nonce: None,
        code_challenge: "challenge".to_owned(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: Some("session-hash".to_owned()),
        holder_hash: Some("holder-hash".to_owned()),
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
fn authorization_error_redirects_after_canonical_uri_verification() {
    let mut request = request("https://client.example:443/callback");
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
        .expect("verified canonical redirect location");
    assert!(location.starts_with("https://client.example/callback?"));
    assert!(location.contains("error=unsupported_response_type"));
}

#[test]
fn authorization_error_accepts_a_loopback_ipv4_dynamic_port() {
    let mut client = client();
    client.redirect_uris = vec!["http://127.0.0.1:41000/callback".to_owned()];
    let mut request = request("http://127.0.0.1:52000/callback");
    request.response_type = "token".to_owned();

    let response = authorization_error(
        &request,
        &client,
        AuthorizationRequestError::UnsupportedResponseType,
    );

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("verified loopback redirect location");
    assert!(location.starts_with("http://127.0.0.1:52000/callback?"));
}

#[test]
fn authorization_error_rejects_a_loopback_host_change() {
    let mut client = client();
    client.redirect_uris = vec!["http://127.0.0.1:41000/callback".to_owned()];
    let response = authorization_error(
        &request("http://127.0.0.2:52000/callback"),
        &client,
        AuthorizationRequestError::RedirectUriNotAllowed,
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(LOCATION).is_none());
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

#[test]
fn denial_redirect_rejects_uri_removed_from_current_client_registration() {
    let redirect = super::super::ui_handlers::error_redirect(
        &pending("https://retired.example/callback"),
        &client(),
    );

    assert!(redirect.is_none());
}

#[test]
fn denial_flow_reloads_current_client_before_building_redirect() {
    let denial_branch = UI_HANDLERS_SOURCE
        .split_once("if matches!(decision, ConsentDecision::Deny)")
        .map(|(_, source)| source)
        .and_then(|source| source.split_once("let validated ="))
        .map(|(source, _)| source)
        .expect("authorization denial branch");

    assert!(denial_branch.contains("state.clients.find_registered(&pending.client_id)"));
    assert!(denial_branch.contains("error_redirect(&pending, &client)"));
}

#[test]
fn denial_redirect_uses_canonical_current_registration_uri() {
    let redirect = super::super::ui_handlers::error_redirect(
        &pending("https://client.example:443/callback"),
        &client(),
    )
    .expect("currently registered redirect URI");

    assert!(redirect.starts_with("https://client.example/callback?"));
    assert!(redirect.contains("error=access_denied"));
    assert!(redirect.contains("state=state-1"));
}
