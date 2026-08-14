use super::{
    PasswordAction, PasswordProbe, RuntimePasswordPolicy, decode_runtime_password,
    role_password_client_statements, runtime_password_action,
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
    // 只有 SQLSTATE 28P01（invalid_password）才算"口令不可用"，
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
    // 连接层故障与非口令 28 类提前报错），但该状态必须 fail-safe：没有
    // SQLSTATE 28P01 的证据就写入，等于静默覆盖运维侧轮换过的口令
    // （Issue #349 / #455）。
    assert_eq!(
        runtime_password_action(RuntimePasswordPolicy::Managed, true, None),
        PasswordAction::Skip
    );
}

#[test]
fn client_sql_never_embeds_role_password_secrets() {
    // Issue #456：口令只走绑定参数。这些值若被拼进客户端 SQL，就会进
    // pg_stat_activity / 慢查询 / 代理日志。
    let secrets = [
        "super-secret",
        "o'brien",
        r"back\slash",
        r#"quote"value"#,
        "'; DROP ROLE chenxing_runtime; --",
    ];
    for sql in role_password_client_statements() {
        for secret in secrets {
            assert!(
                !sql.contains(secret),
                "client SQL must not contain {secret:?}: {sql}"
            );
        }
        assert!(
            !sql.contains("PASSWORD '"),
            "client SQL must not interpolate a password literal: {sql}"
        );
    }
}

#[test]
fn password_write_uses_server_format_and_forces_standard_conforming_strings() {
    let [ensure_fn, call_sql] = role_password_client_statements();
    assert!(
        ensure_fn.contains("format('ALTER ROLE %I WITH LOGIN PASSWORD %L'"),
        "server function must quote ident/literal with format %I/%L: {ensure_fn}"
    );
    assert!(
        ensure_fn.contains("SET standard_conforming_strings = on"),
        "function must force standard_conforming_strings=on: {ensure_fn}"
    );
    assert!(
        ensure_fn.contains("current_setting('standard_conforming_strings') IS DISTINCT FROM 'on'"),
        "function must reject a session that cannot honor standard_conforming_strings: {ensure_fn}"
    );
    assert!(
        call_sql.contains("$1") && call_sql.contains("$2"),
        "call site must bind role and password as parameters: {call_sql}"
    );
    assert!(
        !call_sql.contains("ALTER ROLE"),
        "the bound call must not be the ALTER ROLE text itself: {call_sql}"
    );
}

#[test]
fn runtime_password_preserves_quotes_and_backslashes() {
    let password = decode_runtime_password(
        "postgres://chenxing_runtime:o%27brien%5Csecret%22quote@localhost/chenxing_auth",
    )
    .expect("valid special-character runtime password");

    assert_eq!(password, "o'brien\\secret\"quote");
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
fn only_invalid_password_sqlstate_is_auto_reset_evidence() {
    // Issue #455：只有 SQLSTATE 28P01（invalid_password）才是自动重置证据。
    assert!(
        super::is_password_rejection(&database_error(Some("28P01"))),
        "28P01 must count as a password rejection"
    );
}

#[test]
fn generic_authorization_sqlstates_never_reset_the_password() {
    // 28000 是 invalid_authorization_specification，HBA / ident 映射等非口令
    // 原因也会产生。其余 28 类同样不是口令证据。把它们当成 Rejected 会触发
    // ALTER ROLE，撤销运维侧轮换（Issue #455）。
    for code in ["28000", "28P02", "28P03"] {
        assert!(
            !super::is_password_rejection(&database_error(Some(code))),
            "{code} must fail-safe and never trigger ALTER ROLE"
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
