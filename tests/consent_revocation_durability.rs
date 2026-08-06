//! 同意撤销的持久性集成测试（Issue #64 / #65）。
//!
//! 核心回归：**Redis 被清空后撤销必须仍然生效**。撤销前的实现把撤销标记只写在
//! Redis 里，一次 FLUSH、无持久化的重启或故障转移到落后副本就会让标记消失，
//! 已撤销的 refresh token 重新可用。
//!
//! 需要 PostgreSQL 和 Redis：连接串取自 `DATABASE_URL` / `REDIS_URL`，
//! 与 `tests/integration_storage.rs` 保持一致。

use std::env;

use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    clients::{
        domain::ValidatedClientRegistration,
        repository::{self as client_repository, ClientCredential},
    },
    consents::ConsentService,
    db,
    oauth::revocation::TokenRevocationStore,
    users::{
        credentials::hash_password, domain::ValidatedRegistration, repository as user_repository,
    },
};
use redis::AsyncCommands;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("PostgreSQL is required for consent revocation tests");
    db::migrate(&pool).await.expect("database migrations");
    pool
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

/// 建一个用户 + 一个 client，返回 (user_id, client_id)。
async fn seed_user_and_client(
    pool: &chenxing_auth::sqlx::PgPool,
) -> (chenxing_auth::users::domain::UserId, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let user = user_repository::insert_user(
        pool,
        ValidatedRegistration {
            username: format!("consent-user-{suffix}"),
            email: format!("consent-{suffix}@example.com"),
            password: "correct horse battery".to_owned(),
            display_name: Some("Consent User".to_owned()),
        },
        hash_password("correct horse battery".to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert user");

    let client_id = format!("consent-client-{suffix}");
    client_repository::insert_client(
        pool,
        ValidatedClientRegistration {
            client_name: "Consent Client".to_owned(),
            redirect_uris: vec!["https://consent.example/callback".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        },
        client_id.clone(),
        ClientCredential::SecretBasic("client-secret-hash".to_owned()),
    )
    .await
    .expect("insert client");

    (user.id, client_id)
}

/// 直接读 `revoked_at`，验证撤销事实真的落库了。
async fn revoked_at(
    pool: &chenxing_auth::sqlx::PgPool,
    user_id: chenxing_auth::users::domain::UserId,
    client_id: &str,
) -> Option<time::OffsetDateTime> {
    chenxing_auth::sqlx::query_as::<_, (Option<time::OffsetDateTime>,)>(
        "SELECT c.revoked_at FROM user_consents c
         JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE c.user_id = $1 AND oc.client_id = $2",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .expect("read revoked_at")
    .and_then(|(value,)| value)
}

#[tokio::test]
async fn revoking_consent_persists_revoked_at_in_postgres() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    // 授权后未撤销：revoked_at 必须为 NULL
    assert!(revoked_at(&pool, user_id, &client_id).await.is_none());

    assert!(
        consents
            .revoke_for_user(user_id, &client_id)
            .await
            .expect("revoke consent")
    );

    // Issue #64：撤销事实必须持久化在数据库，而不只是 Redis 里的一个键
    assert!(
        revoked_at(&pool, user_id, &client_id).await.is_some(),
        "revoked_at must be set so the revocation survives Redis data loss"
    );
}

#[tokio::test]
async fn revocation_survives_a_full_redis_flush() {
    let pool = database().await;
    let redis = redis_client();
    let consents = ConsentService::new(pool.clone());
    // 生产构造器：Redis 缓存 + PostgreSQL 权威回源
    let revocations = TokenRevocationStore::new_with_pool(redis.clone(), pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    assert!(
        !revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("check before revoke")
    );

    // 按生产路径撤销：先写权威库，再失效缓存
    assert!(
        consents
            .revoke_for_user(user_id, &client_id)
            .await
            .expect("revoke consent")
    );
    revocations
        .revoke_consent(&user_key, &client_id)
        .await
        .expect("cache revocation");
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("check after revoke")
    );

    // 模拟 Redis 丢数据：只删掉这一对的缓存键，等价于 FLUSH / 无持久化重启 /
    // 故障转移到落后副本的效果，但不影响并发执行的其他测试。
    revocations
        .clear_consent(&user_key, &client_id)
        .await
        .expect("simulate redis data loss");

    // Issue #64 的核心断言：缓存没了，撤销依然生效（回源到 PostgreSQL）
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("check after redis loss"),
        "consent revocation must survive Redis data loss"
    );

    // 回源后应回填缓存，下一次判定不再需要查库
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let cached: bool = connection
        .exists(consent_cache_key(&user_key, &client_id))
        .await
        .expect("read cache key");
    assert!(cached, "authoritative lookup must back-fill the cache");
}

#[tokio::test]
async fn cache_only_store_loses_revocation_after_redis_flush() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    // `new` 是仅缓存模式：没有权威回源，正是 Issue #64 描述的脆弱行为
    let revocations = TokenRevocationStore::new(redis_client());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent");
    revocations
        .revoke_consent(&user_key, &client_id)
        .await
        .expect("cache revocation");
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("cached revocation")
    );

    revocations
        .clear_consent(&user_key, &client_id)
        .await
        .expect("simulate redis data loss");

    // 对照组：仅缓存模式下撤销确实会失效。这说明「生产必须用 new_with_pool」
    // 不是风格偏好，而是安全要求；同时锁住 new 的语义，防止有人误把它用在生产。
    assert!(
        !revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("cache-only lookup"),
        "cache-only mode has no authoritative fallback by design"
    );
    // 权威库仍然记着撤销，只是这个 store 看不到
    assert!(revoked_at(&pool, user_id, &client_id).await.is_some());
}

#[tokio::test]
async fn revoked_consent_disappears_from_the_authorized_app_list() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    assert!(
        consents
            .list_for_user(user_id)
            .await
            .expect("list before revoke")
            .iter()
            .any(|app| app.client_id == client_id)
    );

    consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent");

    // 软删除后不再出现在「已授权应用」里，但行还在库中（见上一条测试的 revoked_at 断言）
    assert!(
        !consents
            .list_for_user(user_id)
            .await
            .expect("list after revoke")
            .iter()
            .any(|app| app.client_id == client_id),
        "revoked app must not be listed as authorized"
    );
    // scope 判定也必须失效，否则 refresh token 仍能通过 has_scopes
    assert!(
        !consents
            .has_scopes(user_id, &client_id, &["openid".to_owned()])
            .await
            .expect("scope check after revoke")
    );
}

#[tokio::test]
async fn re_authorizing_clears_the_persisted_revocation() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent");
    assert!(revoked_at(&pool, user_id, &client_id).await.is_some());

    // 重新授权走同一个 upsert 路径，必须把 revoked_at 清回 NULL；
    // 否则回源查询会永久把这个用户判成已撤销，用户再也无法授权该应用。
    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("re-authorize");

    assert!(
        revoked_at(&pool, user_id, &client_id).await.is_none(),
        "re-authorization must clear the persisted revocation"
    );
    assert!(
        !consents
            .is_revoked(user_id, &client_id)
            .await
            .expect("authoritative check")
    );
    assert!(
        consents
            .has_scopes(user_id, &client_id, &["openid".to_owned()])
            .await
            .expect("scopes restored")
    );
}

#[tokio::test]
async fn revoking_twice_is_idempotent_and_keeps_the_first_timestamp() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");
    assert!(
        consents
            .revoke_for_user(user_id, &client_id)
            .await
            .expect("first revoke")
    );
    let first = revoked_at(&pool, user_id, &client_id)
        .await
        .expect("first revoked_at");

    // 第二次没有生效授权可撤销 -> false，handler 幂等返回 204
    assert!(
        !consents
            .revoke_for_user(user_id, &client_id)
            .await
            .expect("second revoke")
    );
    // 首次撤销时刻作为审计证据必须稳定，不被重复请求刷新
    assert_eq!(revoked_at(&pool, user_id, &client_id).await, Some(first));
}

/// 复算 `TokenRevocationStore` 的缓存键，用于直接断言缓存回填。
///
/// 与 `revocation.rs` 的 `consent_key` 保持一致：SHA-256("user:client") 的
/// URL-safe base64（无填充）。键格式属于内部实现，这里复制一份而不是暴露出来，
/// 以免把缓存布局变成对外契约。
fn consent_cache_key(user_id: &str, client_id: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(format!("{user_id}:{client_id}").as_bytes());
    format!(
        "chenxing:oauth:consent-revoked:{}",
        URL_SAFE_NO_PAD.encode(digest)
    )
}
