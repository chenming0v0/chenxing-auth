use chenxing_auth::keys::KeyManager;

#[test]
fn key_manager_generates_a_public_signing_key() {
    let manager = KeyManager::generate().expect("RSA signing key");
    let jwks = manager.jwks();

    assert_eq!(jwks.keys.len(), 1);
    let key = &jwks.keys[0];
    assert_eq!(key.common.key_id.as_deref(), Some(manager.key_id()));
    assert_eq!(
        key.common.key_algorithm,
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS256)
    );
}
