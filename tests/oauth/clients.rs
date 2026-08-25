use chenxing_auth::clients::domain::{
    ClientRegistrationError, ClientRegistrationInput, validate_client_registration,
};

#[test]
fn client_registration_accepts_exact_https_redirect_uri() {
    let client = validate_client_registration(ClientRegistrationInput {
        client_name: "辰星项目".to_owned(),
        redirect_uris: vec!["https://project.example.com/oauth/callback".to_owned()],
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        logo_uri: None,
        client_uri: None,
    })
    .expect("valid client registration");

    assert_eq!(
        client.redirect_uris[0],
        "https://project.example.com/oauth/callback"
    );
    assert_eq!(client.scopes, vec!["openid", "profile"]);
}

#[test]
fn client_registration_rejects_http_redirect_uri() {
    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "辰星项目".to_owned(),
        redirect_uris: vec!["http://project.example.com/oauth/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        logo_uri: None,
        client_uri: None,
    })
    .expect_err("production client must use HTTPS");

    assert_eq!(error, ClientRegistrationError::InsecureRedirectUri);
}

#[test]
fn client_registration_rejects_open_redirect_uri() {
    let error = validate_client_registration(ClientRegistrationInput {
        client_name: "辰星项目".to_owned(),
        redirect_uris: vec!["https://project.example.com/*".to_owned()],
        scopes: vec!["openid".to_owned()],
        logo_uri: None,
        client_uri: None,
    })
    .expect_err("wildcard redirect must be rejected");

    assert_eq!(error, ClientRegistrationError::WildcardRedirectUri);
}
