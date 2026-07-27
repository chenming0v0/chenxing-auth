use chenxing_auth::users::domain::{LoginError, LoginInput, validate_login};

#[test]
fn login_normalizes_email() {
    let login = validate_login(LoginInput {
        email: " USER@Example.COM ".to_owned(),
        password: "password".to_owned(),
    })
    .expect("valid login input");

    assert_eq!(login.email, "user@example.com");
}

#[test]
fn login_rejects_invalid_email() {
    let error = validate_login(LoginInput {
        email: "invalid".to_owned(),
        password: "password".to_owned(),
    })
    .expect_err("invalid email must be rejected");

    assert_eq!(error, LoginError::InvalidEmail);
}
