use chenxing_auth::keys::KeyManager;
use chenxing_auth::oauth::token::{decode_access_token, issue_access_token};

#[test]
fn key_manager_generates_a_public_signing_key() {
    let manager = KeyManager::generate().expect("RSA signing key");
    let jwks = manager.jwks();

    assert_eq!(jwks.keys.len(), 1);
    let key = &jwks.keys[0];
    assert_eq!(
        key.common.key_id.as_deref(),
        Some(manager.key_id().as_str())
    );
    assert_eq!(
        key.common.key_algorithm,
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS256)
    );
}

#[test]
fn generated_private_key_uses_aws_lc_rsa_format() {
    let manager = KeyManager::generate().expect("RSA signing key");
    let token = issue_access_token(
        &manager,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("access token signed by AWS-LC");

    assert!(
        decode_access_token(&manager, "https://auth.example.com", "cx_project", &token,).is_ok()
    );
}

#[test]
fn key_rotation_keeps_previous_public_key_for_token_validation() {
    let manager = KeyManager::generate().expect("signing key");
    let old_key_id = manager.key_id().to_owned();
    let old_token = issue_access_token(
        &manager,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("old access token");

    manager.rotate().expect("rotated signing key");

    assert_ne!(manager.key_id(), old_key_id);
    assert_eq!(manager.jwks().keys.len(), 2);
    assert!(
        decode_access_token(
            &manager,
            "https://auth.example.com",
            "cx_project",
            &old_token,
        )
        .is_ok()
    );
}

#[test]
fn key_manager_clones_share_rotated_active_key() {
    let manager = KeyManager::generate().expect("signing key");
    let clone = manager.clone();
    manager.rotate().expect("rotated signing key");

    assert_eq!(clone.key_id(), manager.key_id());
    assert_eq!(clone.jwks(), manager.jwks());
}
