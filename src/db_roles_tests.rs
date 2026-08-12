use super::{
    PasswordAction, PasswordProbe, RuntimePasswordPolicy, decode_runtime_password, quote_ident,
    quote_literal, runtime_password_action,
};

#[test]
fn unmanaged_policy_never_touches_the_runtime_password() {
    // 运维用外部密钥托管管理口令时，migrate 一步都不能碰，哪怕角色刚被创建。
    for role_existed in [true, false] {
        for probe in [
            None,
            Some(PasswordProbe::Accepted),
            Some(PasswordProbe::Rejected),
        ] {
            assert_eq!(
                runtime_password_action(RuntimePasswordPolicy::Unmanaged, role_existed, probe),
                PasswordAction::Skip
            );
        }
    }
}

#[test]
fn accepted_password_is_left_alone() {
    // Issue #281 的核心：口令已经能登录就不重写，运维侧的轮换不会被覆盖。
    assert_eq!(
        runtime_password_action(
            RuntimePasswordPolicy::Managed,
            true,
            Some(PasswordProbe::Accepted)
        ),
        PasswordAction::Keep
    );
}

#[test]
fn explicitly_rejected_password_is_rewritten() {
    // 只有服务端明确拒绝认证（SQLSTATE 28P01 / 28000）才算"口令不可用"，
    // 此时写入 URL 携带的口令正是 Managed 模式的职责。
    assert_eq!(
        runtime_password_action(
            RuntimePasswordPolicy::Managed,
            true,
            Some(PasswordProbe::Rejected)
        ),
        PasswordAction::Write
    );
}

#[test]
fn freshly_created_role_always_gets_the_password() {
    assert_eq!(
        runtime_password_action(RuntimePasswordPolicy::Managed, false, None),
        PasswordAction::Write
    );
}

#[test]
fn missing_probe_result_never_overwrites() {
    // Managed + 角色已存在 + 探测结果缺失在正常流程中不可达（探测必然执行，
    // 连接层故障提前报错），但该状态必须 fail-safe：没有服务端明确拒绝
    // （SQLSTATE 28P01 / 28000）的证据就写入，等于静默覆盖运维侧轮换过的
    // 口令（Issue #349）。
    assert_eq!(
        runtime_password_action(RuntimePasswordPolicy::Managed, true, None),
        PasswordAction::Skip
    );
}

#[test]
fn identifier_quoting_escapes_embedded_quotes() {
    assert_eq!(quote_ident("chenxing_runtime"), "\"chenxing_runtime\"");
    assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
}

#[test]
fn literal_quoting_escapes_embedded_single_quotes() {
    assert_eq!(quote_literal("secret"), "'secret'");
    assert_eq!(quote_literal("o'brien"), "'o''brien'");
}

#[test]
fn runtime_password_uses_sqlx_percent_decoding_semantics() {
    let password = decode_runtime_password(
        "postgres://chenxing_runtime:p%40ss%3Aword%2F%E4%B8%AD@localhost/chenxing_auth",
    )
    .expect("valid encoded runtime password");

    assert_eq!(password, "p@ss:word/中");
}

#[test]
fn runtime_password_decoding_respects_utf8_byte_boundaries() {
    let password = decode_runtime_password(
        "postgres://chenxing_runtime:%E5%8F%A3%E4%BB%A4%40%F0%9F%94%92@localhost/chenxing_auth",
    )
    .expect("valid multibyte runtime password");

    assert_eq!(password, "口令@🔒");
}

#[test]
fn runtime_password_rejects_malformed_percent_encoding_without_disclosure() {
    for encoded_password in ["secret%", "secret%2", "secret%GG"] {
        let runtime_url =
            format!("postgres://chenxing_runtime:{encoded_password}@localhost/chenxing_auth");
        let error = decode_runtime_password(&runtime_url).expect_err("malformed percent encoding");
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains(encoded_password));
    }
}

#[test]
fn runtime_password_rejects_invalid_utf8_without_disclosure() {
    let encoded_password = "secret%F0%28%8C%28";
    let runtime_url =
        format!("postgres://chenxing_runtime:{encoded_password}@localhost/chenxing_auth");
    let error = decode_runtime_password(&runtime_url).expect_err("invalid UTF-8 password");
    let rendered = format!("{error:?} {error}");

    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains(encoded_password));
}

/// 测试专用的数据库错误：`PgDatabaseError` 没有公开构造器，用一个最小
/// `DatabaseError` 实现模拟服务端返回的 SQLSTATE。
#[derive(Debug)]
struct ProbeError {
    code: Option<&'static str>,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database error (code {:?})", self.code)
    }
}

impl std::error::Error for ProbeError {}

impl crate::sqlx::DatabaseError for ProbeError {
    fn message(&self) -> &str {
        "authentication failed"
    }

    fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
        self.code.map(std::borrow::Cow::Borrowed)
    }

    fn kind(&self) -> sqlx_core::error::ErrorKind {
        sqlx_core::error::ErrorKind::Other
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }
}

fn database_error(code: Option<&'static str>) -> crate::sqlx::Error {
    crate::sqlx::Error::Database(Box::new(ProbeError { code }))
}

#[test]
fn explicit_auth_rejection_codes_are_password_rejections() {
    // Issue #411：只有 SQLSTATE 28P01（口令错误）/ 28000（认证规格被拒）才是
    // 口令不可用的证据。
    for code in ["28P01", "28000"] {
        assert!(
            super::is_password_rejection(&database_error(Some(code))),
            "{code} must count as a password rejection"
        );
    }
}

#[test]
fn connection_level_failures_are_not_password_rejections() {
    // 连接层故障（IO/TLS/DNS）与超时证明不了口令状态：把它们当作认证被拒，
    // 就会让一次网络抖动覆盖掉运维刚轮换的口令（Issue #411）。
    assert!(!super::is_password_rejection(&crate::sqlx::Error::Io(
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused")
    )));
}

#[test]
fn non_auth_database_errors_are_not_password_rejections() {
    // 服务端其他拒绝（如 too many connections）同样不是口令错误。
    assert!(!super::is_password_rejection(&database_error(Some(
        "53300"
    ))));
    assert!(!super::is_password_rejection(&database_error(None)));
}
