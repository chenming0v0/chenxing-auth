use chenxing_auth::users::{
    credentials::MAX_PASSWORD_LENGTH,
    domain::{LoginInput, MAX_IDENTIFIER_LENGTH, validate_login},
};

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

/// Issue #259 的核心回归：超长口令必须在进入 Argon2 之前被拒绝。
///
/// 若上界缺失，这个输入会走完"标识符查不到用户"路径，并对哑哈希执行一次
/// 超长明文的 Argon2——计时填充反而放大了单请求的计算量。
#[test]
fn login_rejects_a_password_beyond_the_upper_bound() {
    let error = validate_login(LoginInput {
        identifier: "user@example.com".to_owned(),
        password: "a".repeat(MAX_PASSWORD_LENGTH + 1),
        totp_code: None,
    })
    .expect_err("password beyond the upper bound must be rejected");

    assert_eq!(error.to_string(), "password is too long");
}

/// 上界按字符数计，与注册侧 `validate_password_length` 保持同一口径。
///
/// 用多字节字符锁死这一点：若实现改用 `len()`（字节数），43 个三字节字符就会
/// 超过 128，长度契约会在登录和注册之间出现漂移。
#[test]
fn login_measures_password_length_in_characters() {
    let login = validate_login(LoginInput {
        identifier: "user@example.com".to_owned(),
        password: "口".repeat(MAX_PASSWORD_LENGTH),
        totp_code: None,
    })
    .expect("a password of exactly the maximum character count must be accepted");

    assert_eq!(login.password.chars().count(), MAX_PASSWORD_LENGTH);
}

#[test]
fn login_accepts_a_password_at_the_upper_bound() {
    let login = validate_login(LoginInput {
        identifier: "user@example.com".to_owned(),
        password: "a".repeat(MAX_PASSWORD_LENGTH),
        totp_code: None,
    })
    .expect("a password at the upper bound must be accepted");

    assert_eq!(login.password.len(), MAX_PASSWORD_LENGTH);
}

/// 登录侧不套用注册期的长度下界（`MIN_PASSWORD_LENGTH` = 10）。
///
/// 存量账号可能持有下界收紧之前设置的短口令，在登录期补下界会把它们直接锁死。
#[test]
fn login_does_not_apply_the_registration_minimum() {
    let login = validate_login(LoginInput {
        identifier: "user@example.com".to_owned(),
        password: "short".to_owned(),
        totp_code: None,
    })
    .expect("a short legacy password must still reach verification");

    assert_eq!(login.password, "short");
}

/// 超长标识符在进入 SQL 与审计哈希之前被拒绝（Issue #259）。
///
/// `is_valid_email` 只要求"有 @、域名含点、无空白"，对长度没有约束，
/// 所以数 MB 的伪邮箱可以通过形态判定并被绑定进凭据查询。
#[test]
fn login_rejects_an_identifier_beyond_the_upper_bound() {
    let local = "a".repeat(MAX_IDENTIFIER_LENGTH);
    let error = validate_login(LoginInput {
        identifier: format!("{local}@example.com"),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect_err("identifier beyond the upper bound must be rejected");

    assert_eq!(error.to_string(), "username or email is invalid");
}

/// 超长标识符与超长口令同时出现时，仍然只返回既有的标识符错误。
///
/// 两者在服务层都归一为 `InvalidLoginInput`，处理器再映射成统一的 401，
/// 因此新增上界不会引入可区分的响应，也不泄露账号是否存在。
#[test]
fn login_rejects_oversized_identifier_and_password_without_new_signal() {
    let local = "a".repeat(MAX_IDENTIFIER_LENGTH);
    let error = validate_login(LoginInput {
        identifier: format!("{local}@example.com"),
        password: "a".repeat(MAX_PASSWORD_LENGTH + 1),
        totp_code: None,
    })
    .expect_err("oversized input must be rejected");

    assert_eq!(error.to_string(), "username or email is invalid");
}

#[test]
fn login_accepts_an_identifier_at_the_upper_bound() {
    let domain = "@example.com";
    let local = "a".repeat(MAX_IDENTIFIER_LENGTH - domain.len());
    let login = validate_login(LoginInput {
        identifier: format!("{local}{domain}"),
        password: "password".to_owned(),
        totp_code: None,
    })
    .expect("an identifier at the upper bound must be accepted");

    assert_eq!(login.identifier.chars().count(), MAX_IDENTIFIER_LENGTH);
}

/// 空口令的错误语义保持不变，不被新增的上界判定改写。
#[test]
fn login_still_rejects_an_empty_password() {
    let error = validate_login(LoginInput {
        identifier: "user@example.com".to_owned(),
        password: String::new(),
        totp_code: None,
    })
    .expect_err("empty password must be rejected");

    assert_eq!(error.to_string(), "password is empty");
}
