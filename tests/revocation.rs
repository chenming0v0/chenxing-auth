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

    assert!(
        store
            .revoke_consent("user-1", "client-1", 2)
            .await
            .expect("revoke consent")
    );
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
        .forget_consent_cache("user-1", "client-1")
        .await
        .expect("clear consent revocation");
    assert!(
        !store
            .is_consent_revoked("user-1", "client-1")
            .await
            .expect("check cleared consent")
    );
}

/// Issue #276：版本围栏拒绝迟到的撤销写入。
///
/// 这是纯 Redis 侧的行为断言，不需要 PostgreSQL：条件写脚本按缓存中已有版本
/// 判定是否落盘。带数据库的完整交错场景见
/// `tests/consent_revocation_durability.rs`。
#[tokio::test]
async fn stale_revocation_write_is_rejected_by_the_version_fence() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL");
    let store = TokenRevocationStore::new(client);
    let user = format!("fence-user-{}", uuid::Uuid::new_v4().simple());

    // 重新授权已经把「v3 已授权」写进缓存
    assert!(
        store
            .activate_consent(&user, "client-1", 3)
            .await
            .expect("record active fence")
    );

    // 撤销链路迟到：它手里的结论来自 v2，比缓存中的 v3 旧
    assert!(
        !store
            .revoke_consent(&user, "client-1", 2)
            .await
            .expect("stale revoke write"),
        "a revocation write older than the cached state must be rejected"
    );
    assert!(
        !store
            .is_consent_revoked(&user, "client-1")
            .await
            .expect("check after stale write"),
        "stale cache must not deny a consent the database has re-authorized"
    );

    // 真正更新的撤销（v4）必须能立即落盘：围栏只挡陈旧写入，不延迟新撤销
    assert!(
        store
            .revoke_consent(&user, "client-1", 4)
            .await
            .expect("fresh revoke write")
    );
    assert!(
        store
            .is_consent_revoked(&user, "client-1")
            .await
            .expect("check after fresh revoke")
    );

    store
        .forget_consent_cache(&user, "client-1")
        .await
        .expect("cleanup");
}

/// 相同版本号描述相同状态，因此允许覆盖（用于读路径回填时续期 TTL）。
#[tokio::test]
async fn writes_at_the_same_version_are_accepted_as_idempotent() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL");
    let store = TokenRevocationStore::new(client);
    let user = format!("idempotent-user-{}", uuid::Uuid::new_v4().simple());

    assert!(
        store
            .revoke_consent(&user, "client-1", 5)
            .await
            .expect("first write")
    );
    assert!(
        store
            .revoke_consent(&user, "client-1", 5)
            .await
            .expect("same-version write")
    );
    assert!(
        store
            .is_consent_revoked(&user, "client-1")
            .await
            .expect("still revoked")
    );

    store
        .forget_consent_cache(&user, "client-1")
        .await
        .expect("cleanup");
}
