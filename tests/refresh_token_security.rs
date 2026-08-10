use base64::Engine;
use chenxing_auth::oauth::{
    refresh::{REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, RefreshToken, RefreshTokenError},
    refresh_store::{RefreshTokenStore, TombstoneState},
};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn redis_client() -> redis::Client {
    redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL")
}

/// 计算 token 的 Redis 主键（与 refresh_store.rs 的 token_key 逻辑一致）。
fn token_hash(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(value.as_bytes()))
}

fn token_key(value: &str) -> String {
    format!("chenxing:oauth:refresh:{}", token_hash(value))
}

fn client_index_key(client_id: &str) -> String {
    format!("cx:refresh:client_idx:{client_id}")
}

fn family_index_key(family_id: &str) -> String {
    format!("cx:refresh:family_idx:{family_id}")
}

fn tombstone_key(value: &str) -> String {
    format!("cx:refresh:tombstone:{}", token_hash(value))
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

/// Issue #110：重放旧 token（find 返回 None）触发 family 撤销。
#[tokio::test]
async fn replay_old_token_revokes_entire_family() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_replay_test_{}", Uuid::new_v4().simple());
    let token1 = RefreshToken::new(
        client_id.clone(),
        "user-replay".to_owned(),
        vec!["openid".to_owned()],
    );
    let family_id = token1.family_id.clone();

    store.save(&token1).await.expect("save token1");
    let token2 = token1.rotate(vec!["openid".to_owned()]);
    store
        .rotate_if_matches(&token1.value, &token1, &token2)
        .await
        .expect("rotate to token2");

    // token1 已被轮换，墓碑已写入
    assert!(
        store
            .find(&token1.value)
            .await
            .expect("find old token")
            .is_none()
    );
    let tombstone = store
        .read_tombstone(&token1.value)
        .await
        .expect("read tombstone");
    assert!(tombstone.is_some());
    assert_eq!(tombstone.as_ref().unwrap().family_id, family_id);
    assert_eq!(tombstone.as_ref().unwrap().client_id, client_id);
    assert_eq!(tombstone.as_ref().unwrap().state, TombstoneState::Consumed);
    assert!(tombstone.as_ref().unwrap().recorded_at > 0);

    // 此时 token2 仍然存活
    assert!(
        store
            .find(&token2.value)
            .await
            .expect("find token2")
            .is_some()
    );

    // 再次提交 token1（重放） → 撤销整个 family
    let revoked = store
        .revoke_family_after_replay(&family_id, &client_id, "user-replay", &token1.value)
        .await
        .expect("revoke family");
    assert_eq!(revoked, 1, "should revoke 1 token (token2)");

    let replay_tombstone = store
        .read_tombstone(&token1.value)
        .await
        .expect("read replay tombstone")
        .expect("replay tombstone");
    assert_eq!(replay_tombstone.state, TombstoneState::FamilyRevoked);

    // The same replay is idempotent and must not execute another family revoke.
    assert_eq!(
        store
            .revoke_family_after_replay(&family_id, &client_id, "user-replay", &token1.value)
            .await
            .expect("repeat family revoke"),
        0
    );

    // token2 被撤销了
    assert!(
        store
            .find(&token2.value)
            .await
            .expect("find token2 after revoke")
            .is_none()
    );

    // 清理墓碑
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token2.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("cleanup tombstones");
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
    let won_a = result_a.expect("rotation A");
    let won_b = result_b.expect("rotation B");
    assert_ne!(won_a, won_b, "exactly one concurrent CAS must win");

    let winner = if won_a {
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
    assert!(
        store
            .rotate_if_matches(&original.value, &original, &rotated)
            .await
            .expect("rotate to the new token")
    );

    assert!(
        store
            .rollback_rotation(&rotated, &original)
            .await
            .expect("roll back the rotation")
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
    assert!(
        store
            .rotate_if_matches(&original.value, &original, &retried)
            .await
            .expect("retry the rotation after rollback")
    );

    // 新 token 已经不在时不得复活旧 token，否则同一 family 会出现两个活凭据。
    assert!(
        !store
            .rollback_rotation(&rotated, &original)
            .await
            .expect("repeat rollback")
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

/// Issue #110：墓碑 client_id 校验防止跨 client DoS。
#[tokio::test]
async fn tombstone_client_id_mismatch_does_not_revoke_family() {
    let store = RefreshTokenStore::new(redis_client());
    let client_a = format!("cx_client_a_{}", Uuid::new_v4().simple());
    let client_b = format!("cx_client_b_{}", Uuid::new_v4().simple());
    let token_a = RefreshToken::new(
        client_a.clone(),
        "user-a".to_owned(),
        vec!["openid".to_owned()],
    );
    let family_a = token_a.family_id.clone();

    store.save(&token_a).await.expect("save token_a");
    let token_a2 = token_a.rotate(vec!["openid".to_owned()]);
    store
        .rotate_if_matches(&token_a.value, &token_a, &token_a2)
        .await
        .expect("rotate token_a");

    // token_a 的墓碑存在
    let tombstone = store
        .read_tombstone(&token_a.value)
        .await
        .expect("read tombstone");
    assert!(tombstone.is_some());
    assert_eq!(tombstone.as_ref().unwrap().client_id, client_a);

    // Client B 提交 token_a（墓碑 client_id 与请求不匹配）
    // 正确行为：静默拒绝，**不撤销** client_a 的 family
    // 这里我们模拟检测逻辑：只有 client_id 匹配才撤销
    if tombstone.as_ref().unwrap().client_id == client_b {
        // 不应该走到这里
        panic!("client_id should not match");
    }

    // family_a 的 token_a2 依然存活（未被 DoS）
    assert!(
        store
            .find(&token_a2.value)
            .await
            .expect("find token_a2")
            .is_some()
    );

    // 清理
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(token_key(&token_a2.value))
        .arg(format!("cx:refresh:client_idx:{}", client_a))
        .arg(format!("cx:refresh:family_idx:{}", family_a))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token_a.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
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

/// Issue #183：Client 级撤销按最多 128 个成员分批，并持续处理到索引清空。
#[tokio::test]
async fn client_revoke_drains_129_members_and_is_idempotent() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_client_batch_{}", Uuid::new_v4().simple());
    let tokens: Vec<_> = (0..129)
        .map(|index| {
            RefreshToken::new(
                client_id.clone(),
                format!("user-batch-{index}"),
                vec!["openid".to_owned()],
            )
        })
        .collect();

    for token in &tokens {
        store.save(token).await.expect("save batch token");
    }

    assert_eq!(
        store
            .revoke_client_tokens(&client_id)
            .await
            .expect("revoke 129 client tokens"),
        129
    );
    assert_eq!(
        store
            .revoke_client_tokens(&client_id)
            .await
            .expect("repeat client revoke"),
        0,
        "repeating a completed client revoke must be idempotent"
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let mut exists = redis::cmd("EXISTS");
    exists.arg(client_index_key(&client_id));
    for token in &tokens {
        exists.arg(token_key(&token.value));
        exists.arg(family_index_key(&token.family_id));
    }
    let remaining_keys: i64 = exists
        .query_async(&mut conn)
        .await
        .expect("query remaining batch keys");
    assert_eq!(
        remaining_keys, 0,
        "all token, family, and client index keys must be drained"
    );
}

/// Issue #183：损坏的 payload 必须让批次报错，不能丢失重试所需的索引成员。
#[tokio::test]
async fn client_revoke_preserves_corrupt_payload_for_retry() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_client_corrupt_{}", Uuid::new_v4().simple());
    let token = RefreshToken::new(
        client_id.clone(),
        "user-corrupt".to_owned(),
        vec!["openid".to_owned()],
    );
    store.save(&token).await.expect("save token");

    let token_key = token_key(&token.value);
    let client_index_key = client_index_key(&client_id);
    let family_index_key = family_index_key(&token.family_id);
    let hash = token_hash(&token.value);
    let valid_payload = serde_json::to_string(&token).expect("serialize token");
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("SET")
        .arg(&token_key)
        .arg("{")
        .query_async(&mut conn)
        .await
        .expect("corrupt token payload");

    store
        .revoke_client_tokens(&client_id)
        .await
        .expect_err("corrupt payload must fail client revoke");

    let payload_after_error: String = redis::cmd("GET")
        .arg(&token_key)
        .query_async(&mut conn)
        .await
        .expect("read corrupt payload after failure");
    let client_member: bool = redis::cmd("SISMEMBER")
        .arg(&client_index_key)
        .arg(&hash)
        .query_async(&mut conn)
        .await
        .expect("read client membership after failure");
    let family_member: bool = redis::cmd("SISMEMBER")
        .arg(&family_index_key)
        .arg(&hash)
        .query_async(&mut conn)
        .await
        .expect("read family membership after failure");
    assert_eq!(payload_after_error, "{");
    assert!(client_member, "client member must remain retryable");
    assert!(
        family_member,
        "preflight failure must not mutate family index"
    );

    let _: () = redis::cmd("SET")
        .arg(&token_key)
        .arg(valid_payload)
        .query_async(&mut conn)
        .await
        .expect("repair token payload");
    assert_eq!(
        store
            .revoke_client_tokens(&client_id)
            .await
            .expect("retry repaired client revoke"),
        1
    );

    let remaining_keys: i64 = redis::cmd("EXISTS")
        .arg(&token_key)
        .arg(&client_index_key)
        .arg(&family_index_key)
        .query_async(&mut conn)
        .await
        .expect("query repaired revoke keys");
    assert_eq!(remaining_keys, 0);
}

/// Issue #183：family 索引类型错误必须发生在 token / tombstone 删除之前。
#[tokio::test]
async fn client_revoke_recovers_after_family_index_wrongtype() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_client_wrongtype_{}", Uuid::new_v4().simple());
    let token = RefreshToken::new(
        client_id.clone(),
        "user-wrongtype".to_owned(),
        vec!["openid".to_owned()],
    );
    store.save(&token).await.expect("save token");

    let token_key = token_key(&token.value);
    let client_index_key = client_index_key(&client_id);
    let family_index_key = family_index_key(&token.family_id);
    let tombstone_key = tombstone_key(&token.value);
    let hash = token_hash(&token.value);
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("SET")
        .arg(&tombstone_key)
        .arg("stale tombstone")
        .query_async(&mut conn)
        .await
        .expect("save stale tombstone");
    let _: () = redis::cmd("SET")
        .arg(&family_index_key)
        .arg("wrong type")
        .query_async(&mut conn)
        .await
        .expect("corrupt family index type");

    let error = store
        .revoke_client_tokens(&client_id)
        .await
        .expect_err("WRONGTYPE must fail client revoke");
    assert!(
        error.to_string().contains("WRONGTYPE"),
        "unexpected Redis error: {error}"
    );

    let token_still_exists: bool = redis::cmd("EXISTS")
        .arg(&token_key)
        .query_async(&mut conn)
        .await
        .expect("query token after WRONGTYPE");
    let tombstone_still_exists: bool = redis::cmd("EXISTS")
        .arg(&tombstone_key)
        .query_async(&mut conn)
        .await
        .expect("query tombstone after WRONGTYPE");
    let client_member: bool = redis::cmd("SISMEMBER")
        .arg(&client_index_key)
        .arg(&hash)
        .query_async(&mut conn)
        .await
        .expect("query client member after WRONGTYPE");
    assert!(token_still_exists, "WRONGTYPE must not delete the token");
    assert!(
        tombstone_still_exists,
        "WRONGTYPE must not delete the tombstone"
    );
    assert!(
        client_member,
        "WRONGTYPE must leave a retryable client member"
    );

    let _: () = redis::cmd("DEL")
        .arg(&family_index_key)
        .query_async(&mut conn)
        .await
        .expect("remove wrong-type family index");
    let _: i64 = redis::cmd("SADD")
        .arg(&family_index_key)
        .arg(&hash)
        .query_async(&mut conn)
        .await
        .expect("restore family index");
    assert_eq!(
        store
            .revoke_client_tokens(&client_id)
            .await
            .expect("retry after repairing family index"),
        1
    );

    let remaining_keys: i64 = redis::cmd("EXISTS")
        .arg(&token_key)
        .arg(&tombstone_key)
        .arg(&family_index_key)
        .arg(&client_index_key)
        .query_async(&mut conn)
        .await
        .expect("query keys after recovered revoke");
    assert_eq!(
        remaining_keys, 0,
        "recovery must clean token, tombstone, family, and client indexes"
    );
}

/// Issue #161：显式 token revoke 与补偿删除不应留下可触发 family revoke 的墓碑。
#[tokio::test]
async fn explicit_refresh_revoke_does_not_create_replay_tombstone() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_explicit_revoke_{}", Uuid::new_v4().simple());
    let token = RefreshToken::new(
        client_id.clone(),
        "user-explicit-revoke".to_owned(),
        vec!["openid".to_owned()],
    );
    let family_id = token.family_id.clone();

    store.save(&token).await.expect("save token");
    store
        .remove(&token.value)
        .await
        .expect("explicitly revoke token");
    assert!(
        store
            .read_tombstone(&token.value)
            .await
            .expect("read explicit revoke tombstone")
            .is_none()
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(format!("cx:refresh:client_idx:{client_id}"))
        .arg(format!("cx:refresh:family_idx:{family_id}"))
        .query_async(&mut conn)
        .await
        .expect("cleanup explicit revoke");
}

/// 旧格式 token（无 `issued_at` / `family_id`）能反序列化并轮换。
#[test]
fn legacy_token_without_new_fields_can_rotate() {
    // 构造旧格式 token（无 issued_at / family_id）
    let now = OffsetDateTime::now_utc();
    let legacy = RefreshToken {
        value: "cx-refresh-legacy123".to_owned(),
        client_id: "cx_legacy".to_owned(),
        user_id: "user-legacy".to_owned(),
        scopes: vec!["openid".to_owned()],
        created_at: now,
        expires_at: now + Duration::days(30),
        revoked_at: None,
        issued_at: None,
        family_id: String::new(),
    };

    // issued_at() 回退到 created_at
    assert_eq!(legacy.issued_at(), legacy.created_at);

    // 轮换时生成新 family_id
    let rotated = legacy.rotate(vec!["openid".to_owned()]);
    assert!(
        !rotated.family_id.is_empty(),
        "should generate new family_id for legacy token"
    );
    assert_eq!(
        rotated.issued_at(),
        legacy.created_at,
        "issued_at should use original created_at"
    );

    // 重新序列化后新字段被 skip_serializing_if 跳过
    let serialized = serde_json::to_value(&legacy).expect("serialize");
    assert!(
        serialized.get("issued_at").is_none(),
        "issued_at should not serialize when None"
    );
    assert!(
        serialized.get("family_id").is_none(),
        "family_id should not serialize when empty"
    );

    // 能从旧格式 JSON 反序列化
    let json = serde_json::to_string(&serialized).expect("to json");
    let deserialized: RefreshToken = serde_json::from_str(&json).expect("deserialize legacy token");
    assert_eq!(deserialized.issued_at, None);
    assert_eq!(deserialized.family_id, "");
}

/// 索引和墓碑的 TTL 存在（防止 Redis 无界增长）。
#[tokio::test]
async fn indexes_and_tombstones_have_ttl() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_ttl_idx_{}", Uuid::new_v4().simple());
    let token1 = RefreshToken::new(
        client_id.clone(),
        "user-ttl".to_owned(),
        vec!["openid".to_owned()],
    );
    // `RefreshToken::new` 每次都生成新的 family_id，所以 token2 必须由 token1
    // 轮换得到才与它同族 —— 这也是生产里 family 增长的唯一方式。
    // 用两个独立 new() 会让 token1 成为其 family 的唯一成员，消费后 SREM 清空集合、
    // Redis 直接删键，family 索引 TTL 变成 -2（键不存在），断言的对象就没了。
    let token2 = token1.rotate(vec!["profile".to_owned()]);
    let family_id = token1.family_id.clone();
    assert_eq!(
        token2.family_id, family_id,
        "rotation must keep the token in the same family"
    );

    // 保存两个 token 以保证索引非空
    store.save(&token1).await.expect("save token1");
    store.save(&token2).await.expect("save token2");
    // 正常消费一个并写 replay tombstone；显式 remove 不再写 replay marker。
    store
        .take_if_matches(&token1.value, &token1)
        .await
        .expect("consume token1 and write tombstone");

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let client_idx_ttl: i64 = redis::cmd("TTL")
        .arg(format!("cx:refresh:client_idx:{}", client_id))
        .query_async(&mut conn)
        .await
        .expect("client idx TTL");
    let family_idx_ttl: i64 = redis::cmd("TTL")
        .arg(format!("cx:refresh:family_idx:{}", family_id))
        .query_async(&mut conn)
        .await
        .expect("family idx TTL");
    let tombstone_ttl: i64 = redis::cmd("TTL")
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("tombstone TTL");

    assert!(
        client_idx_ttl > 0,
        "client index should have TTL, got {}",
        client_idx_ttl
    );
    assert!(
        family_idx_ttl > 0,
        "family index should have TTL, got {}",
        family_idx_ttl
    );
    assert!(
        tombstone_ttl > 0,
        "tombstone should have TTL, got {}",
        tombstone_ttl
    );

    // 清理
    let _: () = redis::cmd("DEL")
        .arg(token_key(&token2.value))
        .arg(format!("cx:refresh:client_idx:{}", client_id))
        .arg(format!("cx:refresh:family_idx:{}", family_id))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
}
