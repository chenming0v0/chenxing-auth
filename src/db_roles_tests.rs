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
            Some(PasswordProbe::NotAccepted),
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
fn rejected_password_is_rewritten() {
    assert_eq!(
        runtime_password_action(
            RuntimePasswordPolicy::Managed,
            true,
            Some(PasswordProbe::NotAccepted)
        ),
        PasswordAction::Write
    );
}

#[test]
fn unreachable_probe_falls_back_to_writing_the_password() {
    // 探测缺失（库暂时连不上、超时）时退回历史行为，不引入新的启动失败模式。
    assert_eq!(
        runtime_password_action(RuntimePasswordPolicy::Managed, true, None),
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
