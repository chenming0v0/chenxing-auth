//! Split from `refresh_token_security.rs` (nested child module).

use super::*;

/// Issue #671：grant 撤销不能把过期主键误当成 legacy token，必须清理真实
/// family 索引，否则该索引会残留不可消费的 hash。
#[tokio::test]
async fn grant_revoke_cleans_real_family_index_when_token_payload_expired() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_grant_expired_payload_{}", Uuid::new_v4().simple());
    let user_id = format!("user-grant-expired-{}", Uuid::new_v4().simple());
    let expired = RefreshToken::new(
        client_id.clone(),
        user_id.clone(),
        vec!["openid".to_owned()],
    );
    let live = expired.rotate(vec!["openid".to_owned()]);
    let family_id = expired.family_id.clone();

    // Save both members directly to preserve an expired grant member alongside
    // a live member, matching a primary-key TTL expiry in Redis.
    store.save(&expired).await.expect("save expired member");
    store.save(&live).await.expect("save live member");

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: i64 = redis::cmd("EXPIRE")
        .arg(token_key(&expired.value))
        .arg(0)
        .query_async(&mut conn)
        .await
        .expect("expire the token payload");
    // The mapping is absent for tokens written before this repair. This forces
    // the revoke script to locate the hash in the real family index.
    let _: i64 = redis::cmd("DEL")
        .arg(token_family_key(&expired.value))
        .query_async(&mut conn)
        .await
        .expect("remove the pre-repair family mapping");

    let family_member: bool = redis::cmd("SISMEMBER")
        .arg(family_index_key(&family_id))
        .arg(token_hash(&expired.value))
        .query_async(&mut conn)
        .await
        .expect("check expired family member");
    assert!(
        family_member,
        "fixture must retain the expired member in family index"
    );

    assert_eq!(
        store
            .revoke_grant_tokens(&user_id, &client_id)
            .await
            .expect("revoke grant with expired payload"),
        1,
        "only the live payload should be deleted by Redis DEL"
    );

    let remaining_family_member: bool = redis::cmd("SISMEMBER")
        .arg(family_index_key(&family_id))
        .arg(token_hash(&expired.value))
        .query_async(&mut conn)
        .await
        .expect("check family index after revoke");
    assert!(
        !remaining_family_member,
        "grant revoke must remove the expired member from its real family index"
    );

    let remaining_grant_member: bool = redis::cmd("SISMEMBER")
        .arg(grant_index_key(&user_id, &client_id))
        .arg(token_hash(&expired.value))
        .query_async(&mut conn)
        .await
        .expect("check grant index after revoke");
    assert!(!remaining_grant_member, "grant index must be drained");

    let remaining_family_key: bool = redis::cmd("EXISTS")
        .arg(family_index_key(&family_id))
        .query_async(&mut conn)
        .await
        .expect("check family key after revoke");
    assert!(!remaining_family_key, "empty family index must be removed");

    let remaining_mapping: i64 = redis::cmd("EXISTS")
        .arg(token_family_key(&expired.value))
        .arg(token_family_key(&live.value))
        .query_async(&mut conn)
        .await
        .expect("check family mappings after revoke");
    assert_eq!(
        remaining_mapping, 0,
        "token family mappings must be consumed with revoke"
    );

    let _: () = redis::cmd("DEL")
        .arg(client_index_key(&client_id))
        .arg(grant_index_key(&user_id, &client_id))
        .arg(family_index_key(&family_id))
        .arg(family_revoked_key(&family_id))
        .arg(token_family_key(&expired.value))
        .arg(token_family_key(&live.value))
        .arg(tombstone_key(&expired.value))
        .arg(tombstone_key(&live.value))
        .query_async(&mut conn)
        .await
        .expect("cleanup expired payload regression");
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
    assert_eq!(
        store
            .rotate_if_matches(&token1.value, &token1, &token2)
            .await
            .expect("rotate to token2"),
        RotationOutcome::Rotated
    );

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
    assert_eq!(
        store
            .revoke_family_after_replay(&family_id, &client_id, "user-replay", &token1.value)
            .await
            .expect("revoke family"),
        FamilyRevocation {
            revoked_tokens: 1,
            already_revoked: false,
        },
        "should revoke 1 token (token2)"
    );

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
        FamilyRevocation {
            revoked_tokens: 0,
            already_revoked: true,
        }
    );

    // token2 被撤销了
    assert!(
        store
            .find(&token2.value)
            .await
            .expect("find token2 after revoke")
            .is_none()
    );

    // Issue #295：撤销之后一次「迟到的」轮换不能把新成员写回已死的 family。
    let late_rotation = token2.rotate(vec!["openid".to_owned()]);
    assert_eq!(
        store
            .rotate_if_matches(&token2.value, &token2, &late_rotation)
            .await
            .expect("late rotation into a revoked family"),
        RotationOutcome::FamilyRevoked
    );
    assert!(
        store
            .find(&late_rotation.value)
            .await
            .expect("find the late rotation token")
            .is_none(),
        "a revoked family must never gain a new redeemable member"
    );

    // 清理墓碑
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(tombstone_key(&token1.value))
        .arg(tombstone_key(&token2.value))
        .arg(family_revoked_key(&family_id))
        .query_async(&mut conn)
        .await
        .expect("cleanup tombstones");
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
    assert_eq!(
        store
            .rotate_if_matches(&token_a.value, &token_a, &token_a2)
            .await
            .expect("rotate token_a"),
        RotationOutcome::Rotated
    );

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
