fn active_value<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        line.strip_prefix(key)?.strip_prefix('=')
    })
}

#[test]
fn generic_environment_template_documents_the_admin_fail_closed_switch() {
    let example = include_str!("../../.env.example");

    assert_eq!(active_value(example, "ADMIN_TOKEN"), Some(""));
    assert!(example.contains("Leaving it unset disables the entire initialized admin API surface"));
    assert!(
        example.contains("Both Bearer and authenticated browser Session requests are rejected")
    );
    assert!(example.contains("first-owner bootstrap endpoint stays public while no owner exists"));
}

#[test]
fn generic_environment_template_defers_webauthn_to_issuer_but_loopback_example_is_explicit() {
    let generic = include_str!("../../.env.example");
    let loopback = include_str!("../../.env.loopback.example");

    assert_eq!(active_value(generic, "WEBAUTHN_RP_ID"), None);
    assert_eq!(active_value(generic, "WEBAUTHN_ORIGIN"), None);
    assert_eq!(active_value(loopback, "COOKIE_SECURE"), Some("false"));
    assert_eq!(active_value(loopback, "WEBAUTHN_RP_ID"), Some("127.0.0.1"));
    assert_eq!(
        active_value(loopback, "WEBAUTHN_ORIGIN"),
        Some("http://127.0.0.1:3000")
    );
}

#[test]
fn api_documents_keep_empty_admin_token_fail_closed_for_both_channels() {
    let openapi = include_str!("../../openapi.yaml");

    assert!(openapi.contains("ADMIN_TOKEN 为空时整个已初始化管理面 fail closed"));
    assert!(openapi.contains("系统 Bearer 与浏览器 Session 两条管理通道都返回 403"));
    assert!(openapi.contains("唯一例外是不存在 Owner 时公开的首个 Owner 初始化接口"));
}
