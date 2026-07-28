use chenxing_auth::users::domain::{LoginInput, validate_login};

#[test]
fn login_normalizes_email() {
    let login = validate_login(LoginInput {
        identifier: " USER@Example.COM ".to_owned(),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect("valid login input");

    assert_eq!(login.identifier, "user@example.com");
}

#[test]
fn login_rejects_invalid_identifier() {
    let error = validate_login(LoginInput {
        identifier: "ab".to_owned(),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect_err("invalid email must be rejected");

    assert_eq!(error.to_string(), "username or email is invalid");
}

#[test]
fn login_accepts_a_username_identifier() {
    let login = validate_login(LoginInput {
        identifier: " ChenXing-User ".to_owned(),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect("username identifier must be accepted");

    assert_eq!(login.identifier, "chenxing-user");
}
