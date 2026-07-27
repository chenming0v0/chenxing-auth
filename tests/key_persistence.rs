use chenxing_auth::keys::KeyManager;
use chenxing_auth::oauth::token::{decode_access_token, issue_access_token};
use std::fs;
use uuid::Uuid;

#[test]
fn key_manager_reloads_the_same_active_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("reloaded key");

    assert_eq!(first.key_id(), second.key_id());
    assert_eq!(first.jwks(), second.jwks());

    let _ = fs::remove_dir_all(directory);
}

#[test]
fn reloaded_key_manager_keeps_rotated_key_for_old_token_validation() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let old_token = issue_access_token(
        &first,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("old access token");
    first.rotate().expect("rotated signing key");

    let second = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert!(
        decode_access_token(
            &second,
            "https://auth.example.com",
            "cx_project",
            &old_token
        )
        .is_ok()
    );

    let _ = fs::remove_dir_all(directory);
}
