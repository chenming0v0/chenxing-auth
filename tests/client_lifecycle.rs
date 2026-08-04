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
fn admin_one_time_secret_paths_do_not_turn_audit_failure_into_a_lost_secret() {
    for action in ["client_create", "client_secret_rotate"] {
        assert!(
            ADMIN_HANDLERS.contains(&format!(
                "record_admin_event_best_effort(&state, actor, \"{action}\""
            )) || ADMIN_HANDLERS.contains(&format!(
                "record_admin_event_best_effort(\n                &state,\n                actor,\n                \"{action}\""
            )),
            "one-time secret action must use the best-effort audit path: {action}"
        );
    }
    assert!(
        ADMIN_HANDLERS
            .contains("client secret response was returned despite audit persistence failure")
    );
}
