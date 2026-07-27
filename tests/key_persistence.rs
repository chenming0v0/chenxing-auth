use chenxing_auth::keys::KeyManager;
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
