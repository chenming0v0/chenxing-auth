use chenxing_auth::oauth::authorization::{
    AuthorizationRequest, AuthorizationRequestError, RegisteredClient,
    validate_authorization_request,
};

mod api;

const FORM: &str = "client_id=cx_parameter_client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid&state=parameter-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

fn client() -> RegisteredClient {
    RegisteredClient {
        client_id: "cx_parameter_client".to_owned(),
        client_name: "Parameter Client".to_owned(),
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

fn request(extra: &str) -> AuthorizationRequest {
    let form = if extra.is_empty() {
        FORM.to_owned()
    } else {
        format!("{FORM}&{extra}")
    };
    serde_urlencoded::from_str(&form).expect("authorization parameters")
}

#[test]
fn default_query_and_empty_parameters_preserve_valid_authorization() {
    for extra in [
        "",
        "response_mode=query",
        "response_mode=",
        "request=",
        "request_uri=",
        "response_mode=&request=&request_uri=",
    ] {
        let validated = validate_authorization_request(&client(), request(extra))
            .expect("default query authorization remains supported");
        assert_eq!(validated.state, "parameter-state");
        assert_eq!(validated.redirect_uri, "https://client.example/callback");
    }
}

#[test]
fn non_query_response_modes_are_rejected() {
    for mode in ["fragment", "form_post", "QUERY", "%20"] {
        let error =
            validate_authorization_request(&client(), request(&format!("response_mode={mode}")))
                .expect_err("unsupported response mode");
        assert_eq!(error, AuthorizationRequestError::UnsupportedResponseMode);
    }
}

#[test]
fn unsupported_request_objects_cannot_fall_back_to_outer_parameters() {
    for (extra, expected) in [
        (
            "request=opaque-jwt",
            AuthorizationRequestError::RequestNotSupported,
        ),
        (
            "request=%20",
            AuthorizationRequestError::RequestNotSupported,
        ),
        (
            "request_uri=https%3A%2F%2Fclient.example%2Frequest.jwt",
            AuthorizationRequestError::RequestUriNotSupported,
        ),
        (
            "request_uri=%20",
            AuthorizationRequestError::RequestUriNotSupported,
        ),
    ] {
        assert_eq!(
            validate_authorization_request(&client(), request(extra))
                .expect_err("Request Object parameters are unsupported"),
            expected,
        );
    }
}

#[test]
fn empty_parameter_presence_is_retained_by_form_parsing() {
    let parsed = request("response_mode=&request=&request_uri=");
    assert_eq!(parsed.response_mode.as_deref(), Some(""));
    assert_eq!(parsed.request.as_deref(), Some(""));
    assert_eq!(parsed.request_uri.as_deref(), Some(""));
    validate_authorization_request(&client(), parsed)
        .expect("RFC 6749 empty values are treated as omitted");
}

#[test]
fn unrelated_unknown_parameters_remain_ignored() {
    validate_authorization_request(
        &client(),
        request("vendor_hint=preferred&future_option=value"),
    )
    .expect("OAuth ignores unrecognized parameters");
}

#[test]
fn client_and_redirect_validation_precedes_unsupported_parameters() {
    let mut invalid_client = request("request=opaque-jwt");
    invalid_client.client_id = "cx_other_client".to_owned();
    assert_eq!(
        validate_authorization_request(&client(), invalid_client).expect_err("invalid client"),
        AuthorizationRequestError::InvalidClient,
    );

    let mut invalid_redirect = request("request_uri=opaque-uri");
    invalid_redirect.redirect_uri = "https://attacker.example/callback".to_owned();
    assert_eq!(
        validate_authorization_request(&client(), invalid_redirect)
            .expect_err("unregistered redirect"),
        AuthorizationRequestError::RedirectUriNotAllowed,
    );
}

#[test]
fn request_object_debug_output_redacts_both_sensitive_parameters() {
    let parsed = request("request=private-jwt&request_uri=https%3A%2F%2Fsecret.example%2Fjwt");
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("private-jwt"));
    assert!(!debug.contains("secret.example"));
}
