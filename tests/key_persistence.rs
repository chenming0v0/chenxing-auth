use chenxing_auth::keys::KeyManager;
use chenxing_auth::oauth::token::{decode_access_token, issue_access_token};
use std::fs;
use std::time::Duration;
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

#[tokio::test]
async fn reloaded_key_manager_keeps_rotated_key_for_old_token_validation() {
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
    first.rotate().await.expect("rotated signing key");

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

#[tokio::test]
async fn revoking_a_persisted_key_removes_its_file_and_published_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let revoked_key_id = manager.key_id();
    let revoked_key_path = directory.join(format!("rs256-{revoked_key_id}.pkcs1.der"));
    manager.rotate().await.expect("rotated signing key");

    manager
        .revoke(&revoked_key_id)
        .await
        .expect("revoked persisted key");

    assert!(!revoked_key_path.exists());
    assert!(manager.verification_key_for(&revoked_key_id).is_err());
    assert_eq!(manager.jwks().keys.len(), 1);
    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert!(reloaded.verification_key_for(&revoked_key_id).is_err());
    assert_eq!(reloaded.jwks().keys.len(), 1);

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn revoking_a_persisted_active_key_switches_before_removing_it() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let previous_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");
    let active_key_id = manager.key_id();
    let active_key_path = directory.join(format!("rs256-{active_key_id}.pkcs1.der"));

    let revocation = manager
        .revoke(&active_key_id)
        .await
        .expect("revoked active persisted key");

    assert_eq!(revocation.active_key_id, previous_key_id);
    assert_eq!(manager.key_id(), previous_key_id);
    assert!(!active_key_path.exists());
    assert_eq!(
        fs::read_to_string(directory.join("active-rs256.kid")).expect("active key id"),
        previous_key_id
    );

    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert_eq!(reloaded.key_id(), previous_key_id);
    assert!(reloaded.verification_key_for(&active_key_id).is_err());

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn zero_retention_reclaims_old_private_key_after_rotation() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate_with_retention(&directory, Duration::ZERO)
        .expect("initial key");
    let old_key_id = manager.key_id();
    let old_key_path = directory.join(format!("rs256-{old_key_id}.pkcs1.der"));

    manager.rotate().await.expect("rotated signing key");

    assert!(!old_key_path.exists());
    assert_eq!(manager.jwks().keys.len(), 1);
    let reloaded =
        KeyManager::load_or_generate_with_retention(&directory, Duration::ZERO).expect("reload");
    assert_eq!(reloaded.jwks().keys.len(), 1);
    assert!(reloaded.decoding_key_for(&old_key_id).is_err());

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn failed_active_key_persist_keeps_in_memory_key_unchanged() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let old_key_id = manager.key_id();
    let active_path = directory.join("active-rs256.kid");
    fs::remove_file(&active_path).expect("remove active id");
    fs::create_dir(&active_path).expect("block active id replacement");

    assert!(manager.rotate().await.is_err());
    assert_eq!(manager.key_id(), old_key_id);
    assert_eq!(manager.jwks().keys.len(), 1);
    assert_eq!(persisted_key_count(&directory), 1);

    fs::remove_dir(&active_path).expect("remove blocker");
    fs::write(&active_path, &old_key_id).expect("restore active id");
    let reloaded = KeyManager::load_or_generate(&directory).expect("reload after failure");
    assert_eq!(reloaded.key_id(), old_key_id);

    let _ = fs::remove_dir_all(directory);
}

#[test]
fn legacy_private_key_is_migrated_and_removed() {
    let source_directory =
        std::env::temp_dir().join(format!("chenxing-key-source-{}", Uuid::new_v4()));
    let source = KeyManager::load_or_generate(&source_directory).expect("source key");
    let key_id = source.key_id();
    let key_path = source_directory.join(format!("rs256-{key_id}.pkcs1.der"));
    let der = fs::read(key_path).expect("source private key");

    let directory = std::env::temp_dir().join(format!("chenxing-legacy-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("legacy directory");
    fs::write(directory.join("active-rs256.pkcs1.der"), der).expect("legacy private key");
    fs::write(directory.join("active-rs256.kid"), &key_id).expect("legacy active id");

    let manager = KeyManager::load_or_generate(&directory).expect("migrate legacy key");
    assert_eq!(manager.key_id(), key_id);
    assert!(!directory.join("active-rs256.pkcs1.der").exists());
    assert!(directory.join(format!("rs256-{key_id}.pkcs1.der")).exists());

    let _ = fs::remove_dir_all(source_directory);
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn signing_key_storage_permissions_are_restricted_and_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("directory mode");
    let key_path = directory.join("rs256-cx-existing.pkcs1.der");
    let active_path = directory.join("active-rs256.kid");
    fs::write(&key_path, b"invalid-key-material").expect("key file");
    fs::write(&active_path, "cx-existing").expect("active key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("key mode");
    fs::set_permissions(&active_path, fs::Permissions::from_mode(0o644)).expect("active mode");

    let result = KeyManager::load_or_generate(&directory);
    assert!(result.is_err());
    assert_eq!(
        fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&key_path)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&active_path)
            .expect("active metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn provider_secret_storage_permissions_are_restricted_and_repaired() {
    use chenxing_auth::oauth::providers::secrets::SecretManager;
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!("chenxing-secrets-{}", Uuid::new_v4()));
    let manager = SecretManager::load_or_generate(&directory).expect("provider secret");
    let path = manager.path().expect("provider secret path");
    assert_eq!(
        fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path)
            .expect("secret metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("secret mode");
    let reloaded = SecretManager::load_or_generate(&directory).expect("reloaded provider secret");
    assert_eq!(
        fs::metadata(reloaded.path().expect("reloaded path"))
            .expect("reloaded metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn concurrent_rotations_are_serialized_without_losing_keys() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let manager = manager.clone();
        tasks.push(tokio::spawn(async move { manager.rotate().await }));
    }

    let mut key_ids = Vec::new();
    for task in tasks {
        key_ids.push(task.await.expect("rotation task").expect("rotation"));
    }
    key_ids.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    key_ids.dedup_by(|left, right| left.key_id == right.key_id);
    assert_eq!(key_ids.len(), 4);
    assert_eq!(manager.jwks().keys.len(), 5);

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn managers_refresh_shared_active_key_before_signing_and_verifying() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("second manager");

    let rotation = first.rotate().await.expect("rotate signing key");
    let signing_key = second
        .active_signing_key()
        .expect("refresh active signing key");
    assert_eq!(signing_key.key_id(), rotation.key_id);

    let token = issue_access_token(
        &second,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("sign with refreshed key");
    let header = jsonwebtoken::decode_header(&token).expect("token header");
    assert_eq!(header.kid.as_deref(), Some(rotation.key_id.as_str()));
    decode_access_token(&second, "https://auth.example.com", "cx_project", &token)
        .expect("verify with refreshed key");

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn concurrent_manager_rotations_converge_on_shared_active_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("second manager");

    let (first_rotation, second_rotation) = tokio::join!(first.rotate(), second.rotate());
    let first_rotation = first_rotation.expect("first rotation");
    let second_rotation = second_rotation.expect("second rotation");
    assert_ne!(first_rotation.key_id, second_rotation.key_id);

    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    let active_key_id = reloaded.key_id();
    assert!(
        active_key_id == first_rotation.key_id || active_key_id == second_rotation.key_id,
        "disk active key must be one of the serialized rotations"
    );
    assert_eq!(reloaded.jwks().keys.len(), 3);
    assert_eq!(
        first
            .active_signing_key()
            .expect("first manager refresh")
            .key_id(),
        active_key_id.as_str()
    );
    assert_eq!(
        second
            .active_signing_key()
            .expect("second manager refresh")
            .key_id(),
        active_key_id.as_str()
    );

    let _ = fs::remove_dir_all(directory);
}

fn persisted_key_count(directory: &std::path::Path) -> usize {
    fs::read_dir(directory)
        .expect("key directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("rs256-") && name.ends_with(".pkcs1.der"))
        })
        .count()
}
