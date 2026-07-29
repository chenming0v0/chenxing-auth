use chenxing_auth::users::domain::{RegistrationError, RegistrationInput, validate_registration};

#[test]
fn registration_normalizes_email_and_keeps_display_name() {
    let result = validate_registration(RegistrationInput {
        email: "  User@Example.COM ".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: Some("辰星用户".to_owned()),
    })
    .expect("valid registration");

    assert_eq!(result.email, "user@example.com");
    assert_eq!(result.display_name.as_deref(), Some("辰星用户"));
}

#[test]
fn registration_accepts_a_ten_character_password() {
    let result = validate_registration(RegistrationInput {
        email: "user@example.com".to_owned(),
        password: "1234567890".to_owned(),
        display_name: None,
    });

    assert!(result.is_ok());
}

#[test]
fn registration_rejects_short_password() {
    let error = validate_registration(RegistrationInput {
        email: "user@example.com".to_owned(),
        password: "too-short".to_owned(),
        display_name: None,
    })
    .expect_err("short password must be rejected");

    assert_eq!(error, RegistrationError::PasswordTooShort);
}

#[test]
fn registration_rejects_invalid_email() {
    let error = validate_registration(RegistrationInput {
        email: "not-an-email".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: None,
    })
    .expect_err("invalid email must be rejected");

    assert_eq!(error, RegistrationError::InvalidEmail);
}
