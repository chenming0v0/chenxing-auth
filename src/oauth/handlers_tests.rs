use super::super::authorization::{AuthorizationRequestError, MAX_STATE_LENGTH};
use super::*;
use axum::http::{StatusCode, header::LOCATION};

fn client() -> super::super::authorization::RegisteredClient {
    super::super::authorization::RegisteredClient {
        client_id: "client-1".to_owned(),
        client_name: "Test Client".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        owner_user_id: None,
        logo_uri: None,
        client_uri: None,
        description: None,
        numeric_app_id: 1,
        android_package: None,
        quota_exempt: false,
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
        prompt: None,
        max_age: None,
    }
}

#[test]
fn get_and_post_authorize_inputs_preserve_oidc_prompt_and_max_age() {
    let query = "client_id=client-1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid&state=state-1&code_challenge=challenge&code_challenge_method=S256&prompt=login%20consent&max_age=60";
    let get_request: AuthorizationRequest =
        serde_urlencoded::from_str(query).expect("GET query should parse");
    let post_request: AuthorizationRequest =
        serde_urlencoded::from_str(query).expect("POST form should parse");

    assert_eq!(get_request.prompt.as_deref(), Some("login consent"));
    assert_eq!(get_request.max_age, Some(60));
    assert_eq!(post_request.prompt, get_request.prompt);
    assert_eq!(post_request.max_age, get_request.max_age);
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

fn issuer_url(value: &str) -> crate::config::IssuerUrl {
    crate::config::IssuerUrl::parse(value).expect("issuer url")
}

fn android_client(redirect_uri: &str) -> super::super::authorization::RegisteredClient {
    super::super::authorization::RegisteredClient {
        redirect_uris: vec![redirect_uri.to_owned()],
        android_package: Some("com.chengming.termux".to_owned()),
        ..client()
    }
}

/// 已授权直通前的分流判定：同主机 App Link 必须改走确认页（由 SPA 用 intent:// 唤起）。
#[test]
fn preconsented_issuer_app_link_is_routed_to_consent_page() {
    let redirect = "https://oauth.clya.top/app/1/oauth/callback";
    assert!(is_issuer_app_link(
        &issuer_url("https://oauth.clya.top"),
        &android_client(redirect),
        redirect,
    ));
}

/// 普通回调（外部主机、无包名）保持原样：继续直接签发授权码。
#[test]
fn preconsented_ordinary_redirect_keeps_direct_issuance() {
    let issuer = issuer_url("https://oauth.clya.top");
    assert!(!is_issuer_app_link(
        &issuer,
        &client(),
        "https://client.example/callback",
    ));
    let other_host = "https://client.example/app/1/oauth/callback";
    assert!(!is_issuer_app_link(
        &issuer,
        &android_client(other_host),
        other_host
    ));
    let same_host = "https://oauth.clya.top/app/1/oauth/callback";
    let mut no_package = android_client(same_host);
    no_package.android_package = None;
    assert!(!is_issuer_app_link(&issuer, &no_package, same_host));
}
