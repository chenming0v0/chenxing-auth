use chenxing_auth::oauth::authorization::{
    AuthorizationRequest, AuthorizationRequestError, MAX_NONCE_LENGTH, MAX_STATE_LENGTH,
    RegisteredClient, validate_authorization_request,
    validate_authorization_request_with_allowlist,
};

fn client() -> RegisteredClient {
    RegisteredClient {
        client_id: "cx_project".to_owned(),
        client_name: "Project".to_owned(),
        redirect_uris: vec!["https://project.example/callback".to_owned()],
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        owner_user_id: None,
    }
}

fn redirect_uri_is_allowed(registered: &str, requested: &str) -> bool {
    let mut client = client();
    client.redirect_uris = vec![registered.to_owned()];
    validate_authorization_request(
        &client,
        AuthorizationRequest {
            client_id: client.client_id.clone(),
            redirect_uri: requested.to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .is_ok()
}

#[test]
fn loopback_ipv4_redirect_allows_only_the_port_to_change() {
    assert!(redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "http://127.0.0.1:52000/callback?source=native",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "http://127.0.0.2:52000/callback?source=native",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "http://127.0.0.1:52000/other?source=native",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "http://127.0.0.1:52000/callback?source=changed",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "http://127.0.0.1:52000/callback?source=native#fragment",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback?source=native",
        "https://127.0.0.1:52000/callback?source=native",
    ));
}

#[test]
fn loopback_ipv6_redirect_allows_only_the_port_to_change() {
    assert!(redirect_uri_is_allowed(
        "http://[::1]:41000/callback",
        "http://[::1]:52000/callback",
    ));
    assert!(!redirect_uri_is_allowed(
        "http://[::1]:41000/callback",
        "http://[::2]:52000/callback",
    ));
}

#[test]
fn non_loopback_redirects_keep_exact_matching() {
    for (registered, requested) in [
        (
            "https://project.example:41000/callback",
            "https://project.example:52000/callback",
        ),
        (
            "http://localhost:41000/callback",
            "http://localhost:52000/callback",
        ),
        (
            "http://192.0.2.10:41000/callback",
            "http://192.0.2.10:52000/callback",
        ),
    ] {
        assert!(!redirect_uri_is_allowed(registered, requested));
        assert!(redirect_uri_is_allowed(registered, registered));
    }
}

#[test]
fn loopback_port_exception_uses_shared_redirect_uri_canonicalization() {
    assert!(redirect_uri_is_allowed(
        "http://127.0.0.1:41000/callback",
        "http://127.0.0.1:52000/other/../callback",
    ));
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
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect("valid authorization request");

    assert_eq!(request.scopes, vec!["openid", "profile"]);
    assert_eq!(request.nonce.as_deref(), Some("nonce-value"));
}

#[test]
fn authorization_request_canonicalizes_redirect_before_strict_match() {
    let request = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            // Registration stores the canonical form without the default HTTPS port.
            redirect_uri: "https://project.example:443/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid profile".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect("canonical equivalent redirect URI should match");

    assert_eq!(request.redirect_uri, "https://project.example/callback");
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
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
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
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect_err("unregistered scope must be rejected");

    assert_eq!(error, AuthorizationRequestError::ScopeNotAllowed);
}

#[test]
fn authorization_request_rejects_client_scope_outside_server_allowlist() {
    let mut client = client();
    client.scopes.push("admin".to_owned());
    let error = validate_authorization_request_with_allowlist(
        &client,
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "admin".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
        &["openid".to_owned(), "profile".to_owned()],
    )
    .expect_err("server-disallowed client scopes must not authorize");

    assert_eq!(error, AuthorizationRequestError::ScopeNotAllowed);
}

#[test]
fn authorization_consent_decision_accepts_only_approve_or_deny() {
    use chenxing_auth::oauth::consent::{ConsentDecision, parse_decision};

    assert_eq!(parse_decision("approve"), Some(ConsentDecision::Approve));
    assert_eq!(parse_decision("deny"), Some(ConsentDecision::Deny));
    assert_eq!(parse_decision("ignore"), None);
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
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect("nonce is optional when omitted, but blank nonce is normalized away");

    assert_eq!(error.nonce, None);
}

#[test]
fn authorization_request_rejects_state_over_limit() {
    let error = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: Some("x".repeat(MAX_STATE_LENGTH + 1)),
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect_err("overlong state must be rejected before pending creation");

    assert_eq!(error, AuthorizationRequestError::StateTooLong);
}

#[test]
fn authorization_request_rejects_nonce_over_limit() {
    let error = validate_authorization_request(
        &client(),
        AuthorizationRequest {
            client_id: "cx_project".to_owned(),
            redirect_uri: "https://project.example/callback".to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: Some("state-value".to_owned()),
            nonce: Some("x".repeat(MAX_NONCE_LENGTH + 1)),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        },
    )
    .expect_err("overlong nonce must be rejected before pending creation");

    assert_eq!(error, AuthorizationRequestError::NonceTooLong);
}

#[test]
fn authorization_request_rejects_invalid_s256_challenge_before_pending_creation() {
    for challenge in [
        "x".to_owned(),
        "a".repeat(129),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw cM".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-中".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw!cM".to_owned(),
    ] {
        let error = validate_authorization_request(
            &client(),
            AuthorizationRequest {
                client_id: "cx_project".to_owned(),
                redirect_uri: "https://project.example/callback".to_owned(),
                response_type: "code".to_owned(),
                scope: "openid".to_owned(),
                state: Some("state-value".to_owned()),
                nonce: None,
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_owned()),
            },
        )
        .expect_err("invalid S256 challenge must be rejected at authorize");

        assert_eq!(error, AuthorizationRequestError::InvalidCodeChallenge);
    }
}
