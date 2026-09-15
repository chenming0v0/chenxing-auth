use chenxing_auth::oauth::{
    refresh::RefreshToken,
    refresh_store::{RefreshTokenStore, TombstoneState},
};
use uuid::Uuid;

use super::refresh_token_security::{
    client_index_key, family_index_key, redis_client, token_hash, token_key, tombstone_key,
};

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

/// Issue #161：授权码兑换的补偿删除不应留下可触发 family revoke 的墓碑。
///
/// `remove` 销毁的是客户端从未收到的 token，它既不是被消费的凭据，也不是重放
/// 证据。写 `Consumed` 墓碑会让后续提交同一个值被误判成重放并撤销 family。
#[tokio::test]
async fn compensating_removal_does_not_create_replay_tombstone() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_compensating_removal_{}", Uuid::new_v4().simple());
    let token = RefreshToken::new(
        client_id.clone(),
        "user-compensating-removal".to_owned(),
        vec!["openid".to_owned()],
    );
    let family_id = token.family_id.clone();

    store.save(&token).await.expect("save token");
    store
        .remove(&token.value)
        .await
        .expect("remove the never-delivered token");
    assert!(
        store
            .read_tombstone(&token.value)
            .await
            .expect("read compensating removal tombstone")
            .is_none()
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(client_index_key(&client_id))
        .arg(family_index_key(&family_id))
        .query_async(&mut conn)
        .await
        .expect("cleanup compensating removal");
}

/// Issue #356：`remove()` 绝不能销毁重放证据。
///
/// `remove()` 的语义是销毁「客户端从未收到」的 token。若未来任何路径对它
/// 传入一个已存在 `Consumed` 墓碑的 token，删除墓碑会让同一值的再次提交从
/// 「重放 → family 撤销」退化成「未知 token → 静默拒绝」，攻击者获得一次
/// 免费重试。生产流程不会产生「活 token 与墓碑并存」的状态（消费与轮换都
/// 原子地同时删键与写墓碑），但脚本必须在结构上保证任何状态都保留证据：
/// 这里人为构造该组合，直接验证脚本不再触碰墓碑键。
#[tokio::test]
async fn remove_preserves_existing_replay_tombstone() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_remove_preserves_tombstone_{}", Uuid::new_v4().simple());
    let token = RefreshToken::new(
        client_id.clone(),
        "user-remove-tombstone".to_owned(),
        vec!["openid".to_owned()],
    );
    let family_id = token.family_id.clone();

    store.save(&token).await.expect("save token");
    // 人为构造「活 token 与 Consumed 墓碑并存」的状态。
    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let planted = format!(
        r#"{{"family_id":"{family_id}","client_id":"{client_id}","user_id":"user-remove-tombstone","state":"consumed"}}"#
    );
    let _: () = redis::cmd("SET")
        .arg(tombstone_key(&token.value))
        .arg(&planted)
        .query_async(&mut conn)
        .await
        .expect("plant replay tombstone");

    store
        .remove(&token.value)
        .await
        .expect("remove the never-delivered token");
    assert!(
        store
            .find(&token.value)
            .await
            .expect("find removed token")
            .is_none(),
        "remove() must still delete the token itself"
    );
    assert_eq!(
        store
            .read_tombstone(&token.value)
            .await
            .expect("read tombstone after remove")
            .map(|tombstone| tombstone.state),
        Some(TombstoneState::Consumed),
        "remove() must preserve the Consumed replay tombstone"
    );

    let _: () = redis::cmd("DEL")
        .arg(client_index_key(&client_id))
        .arg(family_index_key(&family_id))
        .arg(tombstone_key(&token.value))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
}
