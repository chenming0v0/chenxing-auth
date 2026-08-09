use super::{
    LoginInput, MAX_IDENTIFIER_LENGTH, RegistrationError, RegistrationInput, is_valid_email,
    validate_login, validate_registration,
};

const DOMAIN: &str = "example.com";

fn email_with_length(length: usize) -> String {
    let local_length = length - DOMAIN.len() - 1;
    format!("{}@{DOMAIN}", "a".repeat(local_length))
}

fn registration(email: String) -> RegistrationInput {
    RegistrationInput {
        username: "boundary-user".to_owned(),
        email,
        password: "correct horse battery staple".to_owned(),
        display_name: None,
    }
}

#[test]
fn registration_and_login_accept_the_shared_email_boundary() {
    let email = email_with_length(MAX_IDENTIFIER_LENGTH);
    assert_eq!(email.chars().count(), MAX_IDENTIFIER_LENGTH);
    assert!(is_valid_email(&email));
    assert!(validate_registration(registration(email.clone())).is_ok());
    assert!(
        validate_login(LoginInput {
            identifier: email,
            password: "correct horse battery staple".to_owned(),
        })
        .is_ok()
    );
}

#[test]
fn registration_and_login_reject_email_above_the_shared_boundary() {
    let email = email_with_length(MAX_IDENTIFIER_LENGTH + 1);
    assert!(!is_valid_email(&email));
    assert_eq!(
        validate_registration(registration(email.clone())),
        Err(RegistrationError::InvalidEmail)
    );
    assert!(
        validate_login(LoginInput {
            identifier: email,
            password: "correct horse battery staple".to_owned(),
        })
        .is_err()
    );
}
