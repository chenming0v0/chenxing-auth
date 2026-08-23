use chenxing_auth::users::domain::{
    RegistrationError, RegistrationInput, validate_registration, validate_username,
};

#[test]
fn registration_normalizes_email_and_keeps_display_name() {
    let result = validate_registration(RegistrationInput {
        username: " chenxing-user ".to_owned(),
        email: "  User@Example.COM ".to_owned(),
        password: "correct horse battery".to_owned(),
        display_name: Some("辰星用户".to_owned()),
        invitation_code: None,
    })
    .expect("valid registration");

    // Issue #302：展示值保留用户写的本地部分大小写，只有域名被规范化；
    // 匹配值折叠本地部分。补丁前两者都被压成小写，用户的邮箱拼写在没有必要的
    // 地方被改写。
    assert_eq!(result.email.display(), "User@example.com");
    assert_eq!(result.email.canonical(), "user@example.com");
    assert_eq!(result.username, "chenxing-user");
    assert_eq!(result.display_name.as_deref(), Some("辰星用户"));
}

/// Issue #302：Unicode 域名的等价书写必须收敛到同一个匹配值。
///
/// 补丁前 `to_ascii_lowercase` 只动 ASCII 字节，`ÉXAMPLE.COM` 会留下
/// `Éxample.com`，于是用户按常见小写形式再输入一次就匹配不上，
/// 同时数据库那条 `UNIQUE (email)` 也拦不住重复注册。
#[test]
fn registration_canonicalizes_unicode_domains() {
    let canonical = |email: &str| {
        validate_registration(RegistrationInput {
            username: "unicode-user".to_owned(),
            email: email.to_owned(),
            password: "correct horse battery".to_owned(),
            display_name: None,
            invitation_code: None,
        })
        .expect("valid registration")
        .email
        .into_canonical()
    };

    let expected = "user@xn--xample-9ua.com";
    for variant in [
        "user@éxample.com",
        "user@ÉXAMPLE.COM",
        "USER@Éxample.com",
        "user@xn--xample-9ua.com",
    ] {
        assert_eq!(canonical(variant), expected, "{variant}");
    }
}

#[test]
fn registration_accepts_a_ten_character_password() {
    let result = validate_registration(RegistrationInput {
        username: "ten-char-user".to_owned(),
        email: "user@example.com".to_owned(),
        password: "1234567890".to_owned(),
        display_name: None,
        invitation_code: None,
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
        invitation_code: None,
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
        invitation_code: None,
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
        invitation_code: None,
    })
    .expect_err("short username must be rejected");

    assert_eq!(error, RegistrationError::InvalidUsername);
}

#[test]
fn username_rejects_reserved_names_case_insensitively() {
    for username in ["admin", "SYSTEM", "Owner", "rOoT", "administrator"] {
        assert!(validate_username(username).is_none(), "{username}");
    }
}

#[test]
fn username_rejects_control_and_unsafe_characters() {
    for username in [
        "safe\nname",
        "safe\0name",
        "safe name",
        "safe/name",
        "safe@name",
    ] {
        assert!(validate_username(username).is_none(), "{username:?}");
    }
}

#[test]
fn username_keeps_existing_safe_characters_and_normalization() {
    for (input, expected) in [
        (" ChenXing-User ", "chenxing-user"),
        ("chenxing_user", "chenxing_user"),
        ("user.name", "user.name"),
    ] {
        assert_eq!(validate_username(input).as_deref(), Some(expected));
    }
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
        invitation_code: None,
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
        invitation_code: None,
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
        invitation_code: None,
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
            invitation_code: None,
        })
        .is_ok(),
        "128 multibyte characters must be accepted"
    );
}
