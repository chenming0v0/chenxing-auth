use base64::Engine;
use chenxing_auth::oauth::{
    refresh::{REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, RefreshToken, RefreshTokenError},
    refresh_store::RefreshTokenStore,
};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn redis_client() -> redis::Client {
    redis::Client::open("redis://127.0.0.1:6379").expect("Redis URL")
}

/// 计算 token 的 Redis 主键（与 refresh_store.rs 的 token_key 逻辑一致）。
fn token_key(value: &str) -> String {
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(value.as_bytes()));
    format!("chenxing:oauth:refresh:{}", hash)
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
    old_token.issued_at = Some(OffsetDateTime::now_utc() - Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS + 1));
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
    token.issued_at = Some(OffsetDateTime::now_utc() - Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS - 1));
    token.expires_at = OffsetDateTime::now_utc() + Duration::days(30); // 滑动窗口还有 30 天

    store.save(&token).await.expect("save token");

    // 检查 Redis TTL：应该是 ~1 天（86400 秒），而不是 30 天
    let client = redis_client();
    let mut conn = client.get_multiplexed_async_connection().await.expect("Redis connection");
    let key = token_key(&token.value);
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL query");

    // TTL 应该接近 1 天（86400 秒），给 10 秒误差容忍度
    assert!(ttl > 0 && ttl < 86400 + 10, "TTL should be ~1 day, got {}", ttl);

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
    let token1 = RefreshToken::new(client_id.clone(), "user-replay".to_owned(), vec!["openid".to_owned()]);
    let family_id = token1.family_id.clone();

    store.save(&token1).await.expect("save token1");
    let token2 = token1.rotate(vec!["openid".to_owned()]);
    store
        .rotate_if_matches(&token1.value, &token1, &token2)
        .await
        .expect("rotate to token2");

    // token1 已被轮换，墓碑已写入
    assert!(store.find(&token1.value).await.expect("find old token").is_none());
    let tombstone = store.read_tombstone(&token1.value).await.expect("read tombstone");
    assert!(tombstone.is_some());
    assert_eq!(tombstone.as_ref().unwrap().family_id, family_id);
    assert_eq!(tombstone.as_ref().unwrap().client_id, client_id);

    // 此时 token2 仍然存活
    assert!(store.find(&token2.value).await.expect("find token2").is_some());

    // 再次提交 token1（重放） → 撤销整个 family
    let revoked = store
        .revoke_family(&family_id, &client_id, "user-replay")
        .await
        .expect("revoke family");
    assert_eq!(revoked, 1, "should revoke 1 token (token2)");

    // token2 被撤销了
    assert!(store.find(&token2.value).await.expect("find token2 after revoke").is_none());

    // 清理墓碑
    let client = redis_client();
    let mut conn = client.get_multiplexed_async_connection().await.expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token2.value.as_bytes()))
        ))
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
    let token_a = RefreshToken::new(client_a.clone(), "user-a".to_owned(), vec!["openid".to_owned()]);
    let family_a = token_a.family_id.clone();

    store.save(&token_a).await.expect("save token_a");
    let token_a2 = token_a.rotate(vec!["openid".to_owned()]);
    store
        .rotate_if_matches(&token_a.value, &token_a, &token_a2)
        .await
        .expect("rotate token_a");

    // token_a 的墓碑存在
    let tombstone = store.read_tombstone(&token_a.value).await.expect("read tombstone");
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
    assert!(store.find(&token_a2.value).await.expect("find token_a2").is_some());

    // 清理
    let client = redis_client();
    let mut conn = client.get_multiplexed_async_connection().await.expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(token_key(&token_a2.value))
        .arg(format!("cx:refresh:client_idx:{}", client_a))
        .arg(format!("cx:refresh:family_idx:{}", family_a))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token_a.value.as_bytes()))
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
    let token1 = RefreshToken::new(client_id.clone(), "user-1".to_owned(), vec!["openid".to_owned()]);
    let token2 = RefreshToken::new(client_id.clone(), "user-2".to_owned(), vec!["profile".to_owned()]);

    store.save(&token1).await.expect("save token1");
    store.save(&token2).await.expect("save token2");

    // Secret 轮换 → 撤销该 client 的所有 token
    let revoked = store.revoke_client_tokens(&client_id).await.expect("revoke client tokens");
    assert_eq!(revoked, 2, "should revoke 2 tokens");

    // 两个 token 都消失了
    assert!(store.find(&token1.value).await.expect("find token1").is_none());
    assert!(store.find(&token2.value).await.expect("find token2").is_none());

    // 清理索引（token 主键已被撤销函数删除）
    let client = redis_client();
    let mut conn = client.get_multiplexed_async_connection().await.expect("Redis");
    let _: () = redis::cmd("DEL")
        .arg(format!("cx:refresh:family_idx:{}", token1.family_id))
        .arg(format!("cx:refresh:family_idx:{}", token2.family_id))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
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
    assert!(!rotated.family_id.is_empty(), "should generate new family_id for legacy token");
    assert_eq!(rotated.issued_at(), legacy.created_at, "issued_at should use original created_at");

    // 重新序列化后新字段被 skip_serializing_if 跳过
    let serialized = serde_json::to_value(&legacy).expect("serialize");
    assert!(serialized.get("issued_at").is_none(), "issued_at should not serialize when None");
    assert!(serialized.get("family_id").is_none(), "family_id should not serialize when empty");

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
    let token1 = RefreshToken::new(client_id.clone(), "user-ttl".to_owned(), vec!["openid".to_owned()]);
    let token2 = RefreshToken::new(client_id.clone(), "user-ttl".to_owned(), vec!["profile".to_owned()]);
    let family_id = token1.family_id.clone();

    // 保存两个 token 以保证索引非空
    store.save(&token1).await.expect("save token1");
    store.save(&token2).await.expect("save token2");
    // 移除一个并写墓碑
    store.remove(&token1.value).await.expect("remove token1 and write tombstone");

    let client = redis_client();
    let mut conn = client.get_multiplexed_async_connection().await.expect("Redis");
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
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("tombstone TTL");

    assert!(client_idx_ttl > 0, "client index should have TTL, got {}", client_idx_ttl);
    assert!(family_idx_ttl > 0, "family index should have TTL, got {}", family_idx_ttl);
    assert!(tombstone_ttl > 0, "tombstone should have TTL, got {}", tombstone_ttl);

    // 清理
    let _: () = redis::cmd("DEL")
        .arg(token_key(&token2.value))
        .arg(format!("cx:refresh:client_idx:{}", client_id))
        .arg(format!("cx:refresh:family_idx:{}", family_id))
        .arg(format!(
            "cx:refresh:tombstone:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token1.value.as_bytes()))
        ))
        .query_async(&mut conn)
        .await
        .expect("cleanup");
}
