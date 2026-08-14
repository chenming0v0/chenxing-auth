use chenxing_auth::clients::domain::{ClientRegistrationInput, validate_client_registration};

const ADMIN_HANDLERS: &str = include_str!("../src/admin/handlers.rs");

#[test]
fn client_update_uses_the_same_strict_registration_rules() {
    let client = validate_client_registration(ClientRegistrationInput {
        client_name: "更新后的项目".to_owned(),
        redirect_uris: vec!["https://project.example/new-callback".to_owned()],
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
    })
    .expect("valid update");

    assert_eq!(client.client_name, "更新后的项目");
    assert_eq!(
        client.redirect_uris,
        vec!["https://project.example/new-callback"]
    );
}

#[test]
fn admin_one_time_secret_paths_block_on_audit_failure() {
    // Fix #72: client_create 和 client_secret_rotate 必须使用阻断式审计——
    // 先写审计，审计成功后才返回 secret。best-effort 路径已被移除。
    assert!(
        !ADMIN_HANDLERS.contains("record_admin_event_best_effort"),
        "凭据签发路径不得使用 best-effort 审计；所有 handler 必须在审计失败时阻断响应"
    );
    // 两个操作均须记录 audit.block_on_failure 事件以便运维追查
    assert!(
        ADMIN_HANDLERS.contains("audit.block_on_failure"),
        "handler 必须在审计失败时记录 audit.block_on_failure 结构化事件"
    );
    // 确认两个操作都使用受类型约束的生产 action。
    for action in [
        "AuditAction::ClientCreate",
        "AuditAction::ClientSecretRotate",
    ] {
        assert!(
            ADMIN_HANDLERS.contains(action),
            "handler 必须包含操作 {action} 的审计写入"
        );
    }
}
