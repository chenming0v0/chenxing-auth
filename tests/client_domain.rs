use chenxing_auth::clients::domain::{
    ClientRegistrationError, ClientRegistrationInput, validate_client_registration,
};

#[test]
fn client_registration_trims_and_deduplicates_scopes() {
    let client = validate_client_registration(ClientRegistrationInput {
        client_name: "  项目  ".to_owned(),
        redirect_uris: vec!["https://project.example.com/callback".to_owned()],
        scopes: vec![" openid ".to_owned(), "openid".to_owned()],
    })
    .expect("valid client registration");

    assert_eq!(client.client_name, "项目");
    assert_eq!(client.scopes, vec!["openid"]);
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
