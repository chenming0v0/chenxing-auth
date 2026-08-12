use super::{
    LoginIdentifier, LoginInput, MAX_IDENTIFIER_LENGTH, RegistrationError, RegistrationInput,
    validate_login, validate_registration,
};
use crate::users::email::{EmailAddress, is_valid_email};

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
            totp_code: None,
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
            totp_code: None,
        })
        .is_err()
    );
}

/// Issue #302：注册产出的展示值与匹配值分离，且都由 `EmailAddress` 一次算出。
#[test]
fn registration_separates_display_and_canonical_email() {
    let registration = validate_registration(registration("User@ÉXAMPLE.COM".to_owned()))
        .expect("unicode domain registration must be accepted");

    assert_eq!(registration.email.display(), "User@xn--xample-9ua.com");
    assert_eq!(registration.email.canonical(), "user@xn--xample-9ua.com");
}

/// 登录标识符按形态分流：含 `@` 走邮箱规范化，否则走用户名规范化。
///
/// 这是"两列匹配规则不同"的类型级证据：一个 `String` 无法同时代表两者。
#[test]
fn login_identifier_is_typed_by_shape() {
    let email_login = validate_login(LoginInput {
        identifier: " USER@ÉXAMPLE.COM ".to_owned(),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect("email identifier must be accepted");
    // `EmailAddress` 的相等性按匹配值判定，所以这里的比较不受输入书写影响。
    assert_eq!(
        email_login.identifier,
        LoginIdentifier::Email(
            EmailAddress::parse("user@xn--xample-9ua.com").expect("canonical form parses")
        )
    );
    let LoginIdentifier::Email(ref parsed) = email_login.identifier else {
        panic!("expected an email identifier");
    };
    // 展示值仍然保留原始输入的大小写：相等不等于逐字节相同。
    assert_eq!(parsed.display(), "USER@xn--xample-9ua.com");

    let username_login = validate_login(LoginInput {
        identifier: " ChenXing-User ".to_owned(),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect("username identifier must be accepted");
    assert_eq!(
        username_login.identifier,
        LoginIdentifier::Username("chenxing-user".to_owned())
    );
}

/// 限流键取匹配值：同一账号的不同邮箱书写必须落在同一个失败计数桶里。
///
/// 否则攻击者只要在大小写或 Unicode/Punycode 之间切换书写，就能为同一个账号
/// 换到一个新的配额桶，账号维度的限流形同虚设。
#[test]
fn limiter_key_uses_the_canonical_value() {
    let keys = [
        "USER@ÉXAMPLE.COM",
        "user@xn--xample-9ua.com",
        "User@éxample.com",
    ]
    .map(|raw| {
        validate_login(LoginInput {
            identifier: raw.to_owned(),
            password: "password".to_owned(),
            totp_code: None,
        })
        .expect("valid login")
        .identifier
        .limiter_key()
        .to_owned()
    });

    assert_eq!(keys[0], "user@xn--xample-9ua.com");
    assert!(keys.iter().all(|key| *key == keys[0]), "{keys:?}");
}

/// 含 `@` 的输入不会被当成用户名重试。
///
/// 用户名字符白名单不含 `@`，所以"邮箱解析失败就退回用户名"只会把一个非法邮箱
/// 变成一次无意义的用户名查询；分流必须是互斥的。
#[test]
fn malformed_email_is_not_retried_as_a_username() {
    for identifier in ["user@localhost", "user@", "@example.com", "a@b@example.com"] {
        assert!(
            validate_login(LoginInput {
                identifier: identifier.to_owned(),
                password: "password".to_owned(),
                totp_code: None,
            })
            .is_err(),
            "{identifier}"
        );
    }
}
