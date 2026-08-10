use super::{
    PasswordAction, PasswordProbe, RuntimePasswordPolicy, quote_ident, quote_literal,
    runtime_password_action,
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
