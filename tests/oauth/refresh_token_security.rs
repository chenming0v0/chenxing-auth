use base64::Engine;
use chenxing_auth::oauth::{
    refresh::{REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, RefreshToken, RefreshTokenError},
    refresh_store::{FamilyRevocation, RefreshTokenStore, RotationOutcome, TombstoneState},
};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

mod family_revocation;

pub(super) fn redis_client() -> redis::Client {
    redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL")
}

/// 计算 token 的 Redis 主键（与 refresh_store.rs 的 token_key 逻辑一致）。
pub(super) fn token_hash(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(value.as_bytes()))
}

pub(super) fn token_key(value: &str) -> String {
    format!("chenxing:oauth:refresh:{}", token_hash(value))
}

pub(super) fn client_index_key(client_id: &str) -> String {
    format!("cx:refresh:client_idx:{client_id}")
}

pub(super) fn family_index_key(family_id: &str) -> String {
    format!("cx:refresh:family_idx:{family_id}")
}

pub(super) fn grant_index_key(user_id: &str, client_id: &str) -> String {
    format!("cx:refresh:grant_idx:{user_id}:{client_id}")
}

pub(super) fn token_family_key(value: &str) -> String {
    format!("cx:refresh:token_family:{}", token_hash(value))
}

pub(super) fn tombstone_key(value: &str) -> String {
    format!("cx:refresh:tombstone:{}", token_hash(value))
}

pub(super) fn family_revoked_key(family_id: &str) -> String {
    format!("cx:refresh:family_revoked:{family_id}")
}

#[tokio::test]
async fn final_fence_failure_revokes_a_successor_refresh_token_from_the_grant() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_final_fence_{}", Uuid::new_v4().simple());
    let user_id = format!("user-final-fence-{}", Uuid::new_v4().simple());
    let original = RefreshToken::new(
        client_id.clone(),
        user_id.clone(),
        vec!["openid".to_owned()],
    );
    let successor = original.rotate(vec!["openid".to_owned()]);
    store.save(&original).await.expect("save original token");
    assert_eq!(
        store
            .rotate_if_matches(&original.value, &original, &successor)
            .await
            .expect("rotate successor"),
        RotationOutcome::Rotated
    );
    assert!(
        store
            .find(&successor.value)
            .await
            .expect("find successor")
            .is_some()
    );

    let removed = store
        .revoke_grant_tokens(&user_id, &client_id)
        .await
        .expect("revoke grant after final fence failure");
    assert_eq!(removed, 1);
    assert!(
        store
            .find(&successor.value)
            .await
            .expect("find revoked successor")
            .is_none(),
        "a consent or epoch fence failure must not leave a usable successor"
    );
}

/// Issue #109：绝对生命周期限制生效，轮换不能无限延长有效期。
#[tokio::test]
async fn refresh_token_absolute_lifetime_is_enforced() {
    let token = RefreshToken::new(
        "cx_test_client".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );
    // 人为构造一个 180 天前签发、但 expires_at 还在未来的 token
    let mut old_token = token.clone();
    old_token.issued_at =
        Some(OffsetDateTime::now_utc() - Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS + 1));
    old_token.expires_at = OffsetDateTime::now_utc() + Duration::days(10);

    // 滑动窗口还有 10 天，但绝对生命周期已超 180 天 → 拒绝
    assert_eq!(
        old_token.validate("cx_test_client", OffsetDateTime::now_utc()),
        Err(RefreshTokenError::AbsoluteLifetimeExceeded)
    );
}

/// Issue #109：轮换时继承 `issued_at` 和 `family_id`，绝对截止不重置。
#[tokio::test]
async fn refresh_token_rotation_inherits_issued_at_and_family_id() {
    let original = RefreshToken::new(
        "cx_test_client".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );
    let original_issued_at = original.issued_at();
    let original_family = original.family_id.clone();

    let rotated = original.rotate(vec!["openid".to_owned()]);

    // issued_at 不变（绝对生命周期起点固定）
    assert_eq!(rotated.issued_at(), original_issued_at);
    // family_id 不变（撤销单元）
    assert_eq!(rotated.family_id, original_family);
    // value / created_at 会变（新凭据）
    assert_ne!(rotated.value, original.value);
    assert!(rotated.created_at > original.created_at);
}

/// Issue #109：Redis TTL 被绝对截止时间夹住，不会无限滑动。
#[tokio::test]
async fn redis_ttl_is_clamped_by_absolute_deadline() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_ttl_test_{}", Uuid::new_v4().simple());
    let mut token = RefreshToken::new(
        client_id.clone(),
        "user-ttl".to_owned(),
        vec!["openid".to_owned()],
    );
    // 人为设置 issued_at 为 179 天前（还剩 1 天绝对生命周期）
    token.issued_at =
        Some(OffsetDateTime::now_utc() - Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS - 1));
    token.expires_at = OffsetDateTime::now_utc() + Duration::days(30); // 滑动窗口还有 30 天

    store.save(&token).await.expect("save token");

    // 检查 Redis TTL：应该是 ~1 天（86400 秒），而不是 30 天
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let key = token_key(&token.value);
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL query");

    // TTL 应该接近 1 天（86400 秒），给 10 秒误差容忍度
    assert!(
        ttl > 0 && ttl < 86400 + 10,
        "TTL should be ~1 day, got {}",
        ttl
    );

    // 清理
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .arg(format!("cx:refresh:client_idx:{}", client_id))
        .arg(format!("cx:refresh:family_idx:{}", token.family_id))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
}

/// Issue #161：并发轮换只有一个 CAS 胜者，胜者签发的新 token 不应被竞争
/// 请求误判 replay 而撤销。
#[tokio::test]
async fn concurrent_rotation_keeps_the_single_winner_token_alive() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_concurrent_rotation_{}", Uuid::new_v4().simple());
    let original = RefreshToken::new(
        client_id.clone(),
        "user-concurrent".to_owned(),
        vec!["openid".to_owned()],
    );
    let replacement_a = original.rotate(vec!["openid".to_owned()]);
    let replacement_b = original.rotate(vec!["openid".to_owned()]);
    let family_id = original.family_id.clone();

    store.save(&original).await.expect("save original token");
    let (result_a, result_b) = tokio::join!(
        store.rotate_if_matches(&original.value, &original, &replacement_a),
        store.rotate_if_matches(&original.value, &original, &replacement_b),
    );
    let outcome_a = result_a.expect("rotation A");
    let outcome_b = result_b.expect("rotation B");
    assert_ne!(outcome_a, outcome_b, "exactly one concurrent CAS must win");
    assert!(
        matches!(outcome_a, RotationOutcome::Rotated)
            || matches!(outcome_b, RotationOutcome::Rotated),
        "one of the concurrent rotations must succeed"
    );

    let winner = if outcome_a == RotationOutcome::Rotated {
        &replacement_a
    } else {
        &replacement_b
    };
    assert!(
        store
            .find(&winner.value)
            .await
            .expect("find winning replacement")
            .is_some(),
        "the CAS winner must remain usable after a concurrent loser"
    );
    let tombstone = store
        .read_tombstone(&original.value)
        .await
        .expect("read concurrent tombstone")
        .expect("concurrent tombstone");
    assert_eq!(tombstone.state, TombstoneState::Consumed);

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(token_key(&winner.value))
        .arg(format!("cx:refresh:client_idx:{client_id}"))
        .arg(format!("cx:refresh:family_idx:{family_id}"))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(original.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("cleanup concurrent rotation");
}

/// Issue #290：轮换回滚必须原子完成——新 token 消失、旧 token 复活，
/// 绝不能出现「新 token 还活着，旧 token 也被恢复」的双活凭据。
#[tokio::test]
async fn rotation_rollback_restores_the_previous_token_atomically() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_rollback_{}", Uuid::new_v4().simple());
    let original = RefreshToken::new(
        client_id.clone(),
        "user-rollback".to_owned(),
        vec!["openid".to_owned()],
    );
    let rotated = original.rotate(vec!["openid".to_owned()]);
    let family_id = original.family_id.clone();

    store.save(&original).await.expect("save original token");
    assert_eq!(
        store
            .rotate_if_matches(&original.value, &original, &rotated)
            .await
            .expect("rotate to the new token"),
        RotationOutcome::Rotated
    );

    assert_eq!(
        store
            .rollback_rotation(&rotated, &original)
            .await
            .expect("roll back the rotation"),
        RotationOutcome::Rotated
    );
    assert!(
        store
            .find(&rotated.value)
            .await
            .expect("find the rolled-back token")
            .is_none(),
        "rollback must remove the token the client never received"
    );
    assert_eq!(
        store
            .find(&original.value)
            .await
            .expect("find the restored token")
            .expect("the previous token must be usable again")
            .value,
        original.value
    );
    // 恢复后的旧 token 必须能正常轮换（载荷与 CAS 预期逐字节一致）。
    let retried = original.rotate(vec!["openid".to_owned()]);
    assert_eq!(
        store
            .rotate_if_matches(&original.value, &original, &retried)
            .await
            .expect("retry the rotation after rollback"),
        RotationOutcome::Rotated
    );

    // 新 token 已经不在时不得复活旧 token，否则同一 family 会出现两个活凭据。
    // 键已消失（Issue #312），store 层不再把它误报成 CasMismatch。
    assert_eq!(
        store
            .rollback_rotation(&rotated, &original)
            .await
            .expect("repeat rollback"),
        RotationOutcome::KeyMissing
    );
    assert!(
        store
            .find(&original.value)
            .await
            .expect("find the previous token after a repeated rollback")
            .is_none()
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(token_key(&retried.value))
        .arg(client_index_key(&client_id))
        .arg(family_index_key(&family_id))
        .arg(tombstone_key(&original.value))
        .arg(tombstone_key(&rotated.value))
        .query_async(&mut conn)
        .await
        .expect("cleanup rollback keys");
}

/// Issue #62：Client Secret 轮换后，该 client 的所有 refresh token 失效。
#[tokio::test]
async fn rotate_client_secret_revokes_all_refresh_tokens() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_secret_rotation_{}", Uuid::new_v4().simple());
    let token1 = RefreshToken::new(
        client_id.clone(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );
    let token2 = RefreshToken::new(
        client_id.clone(),
        "user-2".to_owned(),
        vec!["profile".to_owned()],
    );

    store.save(&token1).await.expect("save token1");
    store.save(&token2).await.expect("save token2");

    // Secret 轮换 → 撤销该 client 的所有 token
    let revoked = store
        .revoke_client_tokens(&client_id)
        .await
        .expect("revoke client tokens");
    assert_eq!(revoked, 2, "should revoke 2 tokens");

    // 两个 token 都消失了
    assert!(
        store
            .find(&token1.value)
            .await
            .expect("find token1")
            .is_none()
    );
    assert!(
        store
            .find(&token2.value)
            .await
            .expect("find token2")
            .is_none()
    );
    assert!(
        store
            .read_tombstone(&token1.value)
            .await
            .expect("read secret rotation tombstone")
            .is_none(),
        "client secret revocation must not create replay tombstones"
    );

    // 清理索引（token 主键已被撤销函数删除）
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(format!("cx:refresh:family_idx:{}", token1.family_id))
        .arg(format!("cx:refresh:family_idx:{}", token2.family_id))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
}
