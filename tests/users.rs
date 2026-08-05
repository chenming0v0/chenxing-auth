use chenxing_auth::users::domain::{RegistrationError, RegistrationInput, validate_registration};

#[test]
fn registration_normalizes_email_and_keeps_display_name() {
    let result = validate_registration(RegistrationInput {
        username: " chenxing-user ".to_owned(),
        email: "  User@Example.COM ".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: Some("辰星用户".to_owned()),
    })
    .expect("valid registration");

    assert_eq!(result.email, "user@example.com");
    assert_eq!(result.username, "chenxing-user");
    assert_eq!(result.display_name.as_deref(), Some("辰星用户"));
}

#[test]
fn registration_accepts_a_ten_character_password() {
    let result = validate_registration(RegistrationInput {
        username: "ten-char-user".to_owned(),
        email: "user@example.com".to_owned(),
        password: "1234567890".to_owned(),
        display_name: None,
    });

    assert!(result.is_ok());
}

#[test]
fn registration_rejects_short_password() {
    let error = validate_registration(RegistrationInput {
        username: "short-user".to_owned(),
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
        username: "valid-user".to_owned(),
        email: "not-an-email".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: None,
    })
    .expect_err("invalid email must be rejected");

    assert_eq!(error, RegistrationError::InvalidEmail);
}

#[test]
fn registration_requires_a_valid_username() {
    let error = validate_registration(RegistrationInput {
        username: "ab".to_owned(),
        email: "user@example.com".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: None,
    })
    .expect_err("short username must be rejected");

    assert_eq!(error, RegistrationError::InvalidUsername);
}

// ── Issue #122：口令长度上界 ──────────────────────────────────────────────

/// 129 字符口令必须被拒绝。
///
/// Argon2 的成本随口令长度增长，无上界时单个请求可以提交数 MB 明文，把一次哈希
/// 从 50 ms 放大到数秒。限流按请求数计，拦不住单请求的计算量。
#[test]
fn registration_rejects_password_longer_than_the_upper_bound() {
    let error = validate_registration(RegistrationInput {
        username: "long-password-user".to_owned(),
        email: "user@example.com".to_owned(),
        password: "a".repeat(129),
        display_name: None,
    })
    .expect_err("129-character password must be rejected");

    assert_eq!(error, RegistrationError::PasswordTooLong);
}

/// 边界必须闭合：128 字符恰好通过，129 才拒绝。
#[test]
fn registration_accepts_password_at_the_upper_bound() {
    let result = validate_registration(RegistrationInput {
        username: "boundary-password-user".to_owned(),
        email: "user@example.com".to_owned(),
        password: "a".repeat(128),
        display_name: None,
    });

    assert!(result.is_ok(), "128-character password must be accepted");
}

/// 长度按字符数而不是字节数计：129 个中文字符（387 字节）同样按 129 判定。
#[test]
fn password_length_counts_characters_not_bytes() {
    let error = validate_registration(RegistrationInput {
        username: "multibyte-user".to_owned(),
        email: "user@example.com".to_owned(),
        password: "辰".repeat(129),
        display_name: None,
    })
    .expect_err("129 multibyte characters must be rejected");
    assert_eq!(error, RegistrationError::PasswordTooLong);

    // 128 个中文字符是 384 字节，若按字节判定会被误拒。
    assert!(
        validate_registration(RegistrationInput {
            username: "multibyte-ok-user".to_owned(),
            email: "user@example.com".to_owned(),
            password: "辰".repeat(128),
            display_name: None,
        })
        .is_ok(),
        "128 multibyte characters must be accepted"
    );
}
