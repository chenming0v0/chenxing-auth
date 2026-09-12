//! Redis-only watermark and database epoch marker expire with the absolute session TTL.

use super::*;

/// Issue #263：redis-only 路径的用户级撤销水位必须带过期时间。
///
/// 水位 TTL 取绝对 Session TTL。这里同时断言"水位不会先于它应当拦截的会话键消失"：
/// 会话键 TTL 被同一上限封顶，因此 `session_ttl <= watermark_ttl` 必须成立。
#[tokio::test]
async fn redis_only_revocation_watermark_expires_with_the_absolute_session_ttl() {
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let ttl = Duration::from_secs(120);
    let store = SessionStore::with_redis_key(client.clone(), [0x63; 32]).with_absolute_ttl(ttl);
    // redis-only 路径按字符串 user_id 命名水位键，而 revoke_all_for_user 取 i64。
    // 用一个专属高位区间的 ID，避免与 schema 隔离出来的数据库用户共享 Redis 时碰撞。
    let user_id: i64 = 4_263_000_000_000 + i64::from(std::process::id());
    let watermark = format!("chenxing:session:revoked-before:{user_id}");
    let _: usize = connection
        .del(&watermark)
        .await
        .expect("clear watermark before advance");

    let mut session = Session::new(user_id.to_string(), ttl).expect("session");
    store.save(&mut session, ttl).await.expect("save session");
    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(session_token_hash_bytes(&session.token))
    );
    let session_ttl: i64 = connection
        .ttl(&session_key)
        .await
        .expect("redis-only session key TTL");
    assert!(
        session_ttl > 0 && session_ttl <= 120,
        "session key TTL must stay inside the absolute TTL, got {session_ttl}"
    );

    store
        .revoke_all_for_user(user_id)
        .await
        .expect("advance redis-only watermark");
    let watermark_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the advance");
    assert!(
        watermark_ttl > 110 && watermark_ttl <= 120,
        "watermark must expire with the absolute session TTL, got {watermark_ttl}"
    );
    assert!(
        watermark_ttl >= session_ttl,
        "watermark ({watermark_ttl}s) must outlive the session key it rejects ({session_ttl}s)"
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find session behind watermark")
            .is_none(),
        "attaching a TTL must not weaken revocation"
    );

    // 值不前进的分支同样要刷新 TTL：既覆盖乱序撤销，也让升级前留下的无 TTL 老键
    // 被回收。把水位写成远未来的时刻并去掉 TTL，模拟历史老键。
    let future = OffsetDateTime::now_utc() + time::Duration::days(1);
    let legacy_watermark = future.unix_timestamp_nanos().to_string();
    let _: () = connection
        .set(&watermark, &legacy_watermark)
        .await
        .expect("write legacy watermark without a TTL");
    assert_eq!(
        connection
            .ttl::<_, i64>(&watermark)
            .await
            .expect("legacy watermark TTL"),
        -1,
        "legacy watermark fixture must start without a TTL"
    );
    store
        .revoke_all_for_user(user_id)
        .await
        .expect("refresh watermark without advancing it");
    let refreshed_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the refresh");
    assert!(
        refreshed_ttl > 110 && refreshed_ttl <= 120,
        "a non-advancing revocation must still attach a TTL, got {refreshed_ttl}"
    );
    assert_eq!(
        connection
            .get::<_, String>(&watermark)
            .await
            .expect("watermark value after refresh"),
        legacy_watermark,
        "refreshing the TTL must not move the watermark backwards"
    );

    // 刷新只延长、不缩短：已经更久的存活窗口不能被砍短。
    let _: bool = connection
        .expire(&watermark, 600)
        .await
        .expect("stretch the watermark TTL");
    store
        .revoke_all_for_user(user_id)
        .await
        .expect("revoke against a longer watermark TTL");
    let preserved_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the longer window");
    assert!(
        preserved_ttl > 120,
        "a TTL refresh must never shorten a longer window, got {preserved_ttl}"
    );

    let _: usize = connection
        .del(&[watermark, session_key])
        .await
        .expect("cleanup redis-only watermark keys");
}

/// Issue #263：Postgres + outbox 路径的 `revoked-epoch` 水位同样必须带过期时间。
#[tokio::test]
async fn session_revocation_epoch_marker_expires_with_the_absolute_session_ttl() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("epoch-ttl-{}", Uuid::new_v4().simple()),
            email: email_address(format!("epoch-ttl-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert epoch ttl user");
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&marker)
        .await
        .expect("clear reused user revocation marker");
    let ttl = Duration::from_secs(120);
    let store = SessionStore::with_metadata_and_key(client, pool.clone(), session_store_key())
        .with_absolute_ttl(ttl);
    let mut session = Session::new(user.id.to_string(), ttl).expect("session");
    store.save(&mut session, ttl).await.expect("save session");
    store
        .process_pending_outbox()
        .await
        .expect("flush the save outbox");
    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(session_token_hash_bytes(&session.token))
    );
    let session_ttl: i64 = connection
        .ttl(&session_key)
        .await
        .expect("projected session key TTL from outbox");
    assert!(
        session_ttl > 0 && session_ttl <= 120,
        "outbox projection TTL must stay inside the absolute TTL, got {session_ttl}"
    );

    store
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all sessions");
    store
        .process_pending_outbox()
        .await
        .expect("flush revoke outbox");
    let marker_ttl: i64 = connection
        .ttl(&marker)
        .await
        .expect("revocation epoch marker TTL after revoke");
    assert!(
        marker_ttl > 110 && marker_ttl <= 120,
        "the epoch marker must expire with the absolute session TTL, got {marker_ttl}"
    );
    assert!(
        marker_ttl >= session_ttl,
        "marker ({marker_ttl}s) must outlive the projection it rejects ({session_ttl}s)"
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none(),
        "attaching a TTL must not weaken revocation"
    );

    // 老键迁移与重复投递：epoch 不前进时也要补 TTL。
    // 写一个高于当前 epoch 的值，强制走"不前进"分支。
    let legacy_marker = "1000000";
    let _: () = connection
        .set(&marker, legacy_marker)
        .await
        .expect("write legacy epoch marker without a TTL");
    assert_eq!(
        connection
            .ttl::<_, i64>(&marker)
            .await
            .expect("legacy epoch marker TTL"),
        -1,
        "legacy marker fixture must start without a TTL"
    );
    store
        .revoke_all_for_user(user.id)
        .await
        .expect("second revoke all");
    store
        .process_pending_outbox()
        .await
        .expect("flush the second revoke outbox");
    let refreshed_ttl: i64 = connection
        .ttl(&marker)
        .await
        .expect("epoch marker TTL after the refresh");
    assert!(
        refreshed_ttl > 110 && refreshed_ttl <= 120,
        "a non-advancing revocation must still attach a TTL, got {refreshed_ttl}"
    );
    assert_eq!(
        connection
            .get::<_, String>(&marker)
            .await
            .expect("marker value after refresh"),
        legacy_marker,
        "refreshing the TTL must not roll the epoch marker backwards"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup epoch ttl user");
    let _: usize = connection
        .del(&[marker, session_key])
        .await
        .expect("cleanup epoch ttl keys");
}
