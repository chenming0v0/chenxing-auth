use chenxing_auth::clients::domain::{ClientRegistrationInput, validate_client_registration};

#[test]
fn client_update_uses_the_same_strict_registration_rules() {
    let client = validate_client_registration(ClientRegistrationInput {
        client_name: "更新后的项目".to_owned(),
        redirect_uris: vec!["https://project.example/new-callback".to_owned()],
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
    })
    .expect("valid update");

    assert_eq!(client.client_name, "更新后的项目");
    assert_eq!(
        client.redirect_uris,
        vec!["https://project.example/new-callback"]
    );
}
