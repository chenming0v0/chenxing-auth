use chenxing_auth::keys::{KeyManager, KeyManagerError};
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

#[tokio::test]
async fn key_rotation_keeps_previous_public_key_for_token_validation() {
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

    manager.rotate().await.expect("rotated signing key");

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

#[tokio::test]
async fn key_manager_clones_share_rotated_active_key() {
    let manager = KeyManager::generate().expect("signing key");
    let clone = manager.clone();
    manager.rotate().await.expect("rotated signing key");

    assert_eq!(clone.key_id(), manager.key_id());
    assert_eq!(clone.jwks(), manager.jwks());
}

#[tokio::test]
async fn revoking_a_non_active_key_removes_it_from_verification_and_jwks() {
    let manager = KeyManager::generate().expect("signing key");
    let revoked_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");

    let revocation = manager
        .revoke(&revoked_key_id)
        .await
        .expect("revoked signing key");

    assert_eq!(revocation.key_id, revoked_key_id);
    assert_eq!(manager.jwks().keys.len(), 1);
    assert!(manager.verification_key_for(&revoked_key_id).is_err());
}

#[tokio::test]
async fn revoking_the_only_active_key_fails_without_changing_state() {
    let manager = KeyManager::generate().expect("signing key");
    let active_key_id = manager.key_id();

    assert!(matches!(
        manager.revoke(&active_key_id).await,
        Err(KeyManagerError::NoActiveKeyReplacement)
    ));
    assert_eq!(manager.key_id(), active_key_id);
    assert_eq!(manager.jwks().keys.len(), 1);
}

#[tokio::test]
async fn revoking_the_active_key_switches_to_an_existing_key_atomically() {
    let manager = KeyManager::generate().expect("signing key");
    let previous_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");
    let active_key_id = manager.key_id();

    let revocation = manager
        .revoke(&active_key_id)
        .await
        .expect("revoked active signing key");

    assert_eq!(revocation.active_key_id, previous_key_id);
    assert_eq!(manager.key_id(), previous_key_id);
    assert!(manager.verification_key_for(&active_key_id).is_err());
    assert_eq!(manager.jwks().keys.len(), 1);
}
