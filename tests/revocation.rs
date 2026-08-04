use chenxing_auth::oauth::revocation::TokenRevocationStore;

#[tokio::test]
async fn revoked_access_token_is_rejected_until_its_expiry() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL");
    let store = TokenRevocationStore::new(client);

    store
        .revoke("access-token-for-test", 60)
        .await
        .expect("revoke token");
    assert!(
        store
            .is_revoked("access-token-for-test")
            .await
            .expect("check token")
    );
    assert!(
        !store
            .is_revoked("another-token")
            .await
            .expect("check other token")
    );

    store
        .remove("access-token-for-test")
        .await
        .expect("cleanup revocation");
}

#[tokio::test]
async fn consent_revocation_is_bound_to_one_user_and_client() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL");
    let store = TokenRevocationStore::new(client);

    store
        .revoke_consent("user-1", "client-1")
        .await
        .expect("revoke consent");
    assert!(
        store
            .is_consent_revoked("user-1", "client-1")
            .await
            .expect("check revoked consent")
    );
    assert!(
        !store
            .is_consent_revoked("user-1", "client-2")
            .await
            .expect("check another client consent")
    );
    assert!(
        !store
            .is_consent_revoked("user-2", "client-1")
            .await
            .expect("check another user consent")
    );

    store
        .clear_consent("user-1", "client-1")
        .await
        .expect("clear consent revocation");
    assert!(
        !store
            .is_consent_revoked("user-1", "client-1")
            .await
            .expect("check cleared consent")
    );
}
