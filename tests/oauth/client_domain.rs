use chenxing_auth::clients::domain::{
    ClientRegistrationError, ClientRegistrationInput, ClientRegistrationLimits,
    DEFAULT_MAX_REDIRECT_URI_LENGTH, DEFAULT_MAX_REDIRECT_URIS, DEFAULT_MAX_SCOPE_LENGTH,
    DEFAULT_MAX_SCOPES, validate_client_registration, validate_client_registration_with_limits,
};

#[test]
fn client_registration_trims_and_deduplicates_scopes() {
    let client = validate_client_registration(ClientRegistrationInput {
        client_name: "  项目  ".to_owned(),
        redirect_uris: vec![
            "https://project.example.com/callback".to_owned(),
            " https://project.example.com/callback ".to_owned(),
        ],
        scopes: vec![" openid ".to_owned(), "openid".to_owned()],
    })
    .expect("valid client registration");

    assert_eq!(client.client_name, "项目");
    assert_eq!(
        client.redirect_uris,
        vec!["https://project.example.com/callback"]
    );
    assert_eq!(client.scopes, vec!["openid"]);
}

#[test]
fn client_registration_enforces_configured_collection_limits() {
    let limits = ClientRegistrationLimits::new(1, 64, 1, 16).expect("valid limits");
    let error = validate_client_registration_with_limits(
        ClientRegistrationInput {
            client_name: "项目".to_owned(),
            redirect_uris: vec![
                "https://project.example.com/one".to_owned(),
                "https://project.example.com/two".to_owned(),
            ],
            scopes: vec!["openid".to_owned()],
        },
        &limits,
    )
    .expect_err("redirect count must be bounded");
    assert_eq!(error, ClientRegistrationError::TooManyRedirectUris);

    let error = validate_client_registration_with_limits(
        ClientRegistrationInput {
            client_name: "项目".to_owned(),
            redirect_uris: vec!["https://project.example.com/callback".to_owned()],
            scopes: vec!["s".repeat(17)],
        },
        &limits,
    )
    .expect_err("scope length must use configured limit");
    assert_eq!(error, ClientRegistrationError::ScopeTooLong);
}

#[test]
fn client_registration_rejects_scope_outside_server_allowlist() {
    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "项目".to_owned(),
        redirect_uris: vec!["https://project.example.com/callback".to_owned()],
        scopes: vec!["admin".to_owned()],
    })
    .expect_err("unknown scopes must be rejected");

    assert_eq!(error, ClientRegistrationError::UnsupportedScope);
}

#[test]
fn client_registration_accepts_explicitly_configured_custom_scope() {
    let limits = ClientRegistrationLimits::default()
        .with_allowed_scopes(vec!["openid".to_owned(), "project:read".to_owned()])
        .expect("valid scope allowlist");
    let client = validate_client_registration_with_limits(
        ClientRegistrationInput {
            client_name: "项目".to_owned(),
            redirect_uris: vec!["https://project.example.com/callback".to_owned()],
            scopes: vec!["project:read".to_owned()],
        },
        &limits,
    )
    .expect("configured custom scope");

    assert_eq!(client.scopes, vec!["project:read"]);
}

#[test]
fn client_registration_rejects_boundary_overflows_and_large_json_values() {
    let too_many_redirects =
        vec!["https://project.example.com/callback".to_owned(); DEFAULT_MAX_REDIRECT_URIS + 1];
    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "项目".to_owned(),
        redirect_uris: too_many_redirects,
        scopes: vec!["openid".to_owned()],
    })
    .expect_err("redirect URI collection must be bounded");
    assert_eq!(error, ClientRegistrationError::TooManyRedirectUris);

    let oversized_json = serde_json::json!({
        "client_name": "项目",
        "redirect_uris": [format!(
            "https://project.example.com/{}",
            "x".repeat(DEFAULT_MAX_REDIRECT_URI_LENGTH)
        )],
        "scopes": ["openid"]
    });
    let input: ClientRegistrationInput =
        serde_json::from_value(oversized_json).expect("oversized JSON request shape");
    let error = validate_client_registration(input)
        .expect_err("large JSON value must be rejected before persistence");
    assert_eq!(error, ClientRegistrationError::RedirectUriTooLong);

    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "项目".to_owned(),
        redirect_uris: vec!["https://project.example.com/callback".to_owned()],
        scopes: vec!["scope".to_owned(); DEFAULT_MAX_SCOPES + 1],
    })
    .expect_err("scope collection must be bounded");
    assert_eq!(error, ClientRegistrationError::TooManyScopes);

    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "项目".to_owned(),
        redirect_uris: vec!["https://project.example.com/callback".to_owned()],
        scopes: vec!["界".repeat(DEFAULT_MAX_SCOPE_LENGTH + 1)],
    })
    .expect_err("Unicode scope length must be bounded by characters");
    assert_eq!(error, ClientRegistrationError::ScopeTooLong);
}

#[test]
fn client_registration_rejects_redirect_uri_with_userinfo() {
    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "项目".to_owned(),
        redirect_uris: vec!["https://user:pass@example.com/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
    })
    .expect_err("redirect URI userinfo must be rejected");

    assert_eq!(error, ClientRegistrationError::InvalidRedirectUri);
}
