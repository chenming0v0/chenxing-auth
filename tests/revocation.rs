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

/// 缓存键的绑定语义：一对「用户 × Client」互不影响。
///
/// 这里用仅缓存模式（`new`），只覆盖 Redis 侧的键隔离。
/// 撤销的持久性和权威回源由 `tests/consent_revocation_durability.rs` 覆盖。
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
