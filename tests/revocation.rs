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
