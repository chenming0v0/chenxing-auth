use base64::Engine;
use chenxing_auth::oauth::{
    refresh::RefreshToken,
    refresh_store::{FamilyRevocation, RefreshTokenStore, RotationOutcome, TombstoneState},
};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::refresh_token_security::{
    client_index_key, family_index_key, family_revoked_key, redis_client, token_hash, token_key,
    tombstone_key,
};

/// Issue #295：显式撤销的单元是 grant family，而不是提交的那一个 token。
///
/// 覆盖三件事：轮换后仍存活的后继必须一起死；提交一个已被轮换消费掉的旧
/// token 也要能定位并排空它的 family（撤销请求与轮换竞争时就是这个形状）；
/// 撤销后的重复请求幂等。

#[tokio::test]
async fn explicit_revoke_drains_the_whole_grant_family() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_explicit_family_revoke_{}", Uuid::new_v4().simple());
    let first = RefreshToken::new(
        client_id.clone(),
        "user-explicit-revoke".to_owned(),
        vec!["openid".to_owned()],
    );
    let second = first.rotate(vec!["openid".to_owned()]);
    let family_id = first.family_id.clone();

    store.save(&first).await.expect("save the first token");
    assert_eq!(
        store
            .rotate_if_matches(&first.value, &first, &second)
            .await
            .expect("rotate to the second token"),
        RotationOutcome::Rotated
    );

    // 客户端提交它手里那个已经被轮换掉的旧值：墓碑仍然指向同一个 family。
    assert_eq!(
        store
            .revoke_family_on_explicit_revoke(
                &family_id,
                &client_id,
                "user-explicit-revoke",
                &first.value,
            )
            .await
            .expect("revoke the grant family"),
        FamilyRevocation {
            revoked_tokens: 1,
            already_revoked: false,
        },
        "the live successor must be revoked even though the submitted token was consumed"
    );
    assert!(
        store
            .find(&second.value)
            .await
            .expect("find the successor after revoke")
            .is_none(),
        "explicit revoke must not leave a redeemable successor"
    );

    // 撤销墓碑是 ExplicitRevoke，不是 Consumed：主动撤销不是泄露信号，
    // 后续提交只应得到普通 invalid_grant，不该被记成「检测到重放」。
    for value in [&first.value, &second.value] {
        assert_eq!(
            store
                .read_tombstone(value)
                .await
                .expect("read explicit revoke tombstone")
                .expect("explicit revoke tombstone")
                .state,
            TombstoneState::ExplicitRevoke
        );
    }

    assert_eq!(
        store
            .revoke_family_on_explicit_revoke(
                &family_id,
                &client_id,
                "user-explicit-revoke",
                &second.value,
            )
            .await
            .expect("repeat the explicit revoke"),
        FamilyRevocation {
            revoked_tokens: 0,
            already_revoked: true,
        }
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(client_index_key(&client_id))
        .arg(family_index_key(&family_id))
        .arg(family_revoked_key(&family_id))
        .arg(tombstone_key(&first.value))
        .arg(tombstone_key(&second.value))
        .query_async(&mut conn)
        .await
        .expect("cleanup explicit family revoke");
}

/// 旧格式 token 没有 `family_id`：撤销必须只影响它自己。
///
/// 若这类 token 共用同一个空后缀撤销键，撤销任意一个就会给全部旧 token 写上
/// 同一个墓志，把互不相关的 grant 连坐撤销。
#[tokio::test]
async fn revoking_a_legacy_token_does_not_touch_other_legacy_tokens() {
    let store = RefreshTokenStore::new(redis_client());
    let client_id = format!("cx_legacy_revoke_{}", Uuid::new_v4().simple());
    let now = OffsetDateTime::now_utc();
    let legacy = |suffix: &str| RefreshToken {
        value: format!("cx-refresh-legacy-{}-{suffix}", Uuid::new_v4().simple()),
        client_id: client_id.clone(),
        user_id: "user-legacy-revoke".to_owned(),
        scopes: vec!["openid".to_owned()],
        created_at: now,
        expires_at: now + Duration::days(30),
        revoked_at: None,
        issued_at: None,
        family_id: String::new(),
        client_secret_version: None,
        // 旧格式 payload 没有 session_epoch（Issue #409 之前签发）
        session_epoch: None,
        // 旧格式 payload 没有 issuer_generation（Issue #492 之前签发）
        issuer_generation: None,
        cas_revision: 0,
    };
    let revoked = legacy("revoked");
    let untouched = legacy("untouched");

    store.save(&revoked).await.expect("save the legacy token");
    store
        .save(&untouched)
        .await
        .expect("save the untouched legacy token");

    assert_eq!(
        store
            .revoke_family_on_explicit_revoke("", &client_id, "user-legacy-revoke", &revoked.value)
            .await
            .expect("revoke the legacy token"),
        FamilyRevocation {
            revoked_tokens: 1,
            already_revoked: false,
        }
    );
    assert!(
        store
            .find(&revoked.value)
            .await
            .expect("find the revoked legacy token")
            .is_none()
    );
    assert!(
        store
            .find(&untouched.value)
            .await
            .expect("find the untouched legacy token")
            .is_some(),
        "legacy tokens must not share a revocation scope"
    );

    let client = redis_client();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(token_key(&untouched.value))
        .arg(client_index_key(&client_id))
        .arg(tombstone_key(&revoked.value))
        .arg(family_revoked_key(&format!(
            "legacy-token:{}",
            token_hash(&revoked.value)
        )))
        .query_async(&mut conn)
        .await
        .expect("cleanup legacy revoke");
}

/// 旧格式 token 能反序列化，但缺失的安全代际字段会在兑换路径 fail-closed。
#[test]
fn legacy_token_without_new_fields_can_rotate() {
    // 构造旧格式 token（无 issued_at / family_id / client_secret_version /
    // session_epoch / issuer_generation）。
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
        client_secret_version: None,
        // 旧格式 payload 没有 session_epoch，兑换路径对其 fail-closed
        session_epoch: None,
        // 旧格式 payload 没有 issuer_generation，兑换路径同样 fail-closed
        issuer_generation: None,
        cas_revision: 0,
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
    assert!(
        serialized.get("issuer_generation").is_none(),
        "issuer_generation should not serialize when absent"
    );
    assert!(
        serialized.get("client_secret_version").is_none(),
        "client_secret_version should not serialize when None"
    );

    // 能从旧格式 JSON 反序列化
    let json = serde_json::to_string(&serialized).expect("to json");
    let deserialized: RefreshToken = serde_json::from_str(&json).expect("deserialize legacy token");
    assert_eq!(deserialized.issued_at, None);
    assert_eq!(deserialized.family_id, "");
    assert_eq!(deserialized.client_secret_version, None);
    assert_eq!(deserialized.issuer_generation, None);
    assert!(
        !deserialized.is_bound_to_issuer_generation(1),
        "legacy refresh tokens without an issuer generation must fail closed"
    );
    assert!(
        deserialized.is_bound_to_client_secret_version(7, true),
        "legacy tokens remain usable during the rollout compatibility window"
    );
    assert!(
        !deserialized.is_bound_to_client_secret_version(7, false),
        "a post-upgrade Secret rotation permanently closes the legacy window"
    );
    let rebound =
        deserialized.rotate_at_with_client_secret_version(vec!["openid".to_owned()], 7, now);
    assert_eq!(rebound.client_secret_version, Some(7));
    assert_eq!(rebound.issuer_generation, None);
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
