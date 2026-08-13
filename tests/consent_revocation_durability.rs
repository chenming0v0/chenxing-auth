//! 同意撤销的持久性与写入交错集成测试（Issue #64 / #65 / #276）。
//!
//! 两条核心回归：
//! 1. **Redis 被清空后撤销必须仍然生效**（#64 / #65）。撤销前的实现把撤销标记
//!    只写在 Redis 里，一次 FLUSH、无持久化的重启或故障转移到落后副本就会让
//!    标记消失，已撤销的 refresh token 重新可用。
//! 2. **陈旧缓存不得否决数据库已重新授权的状态**（#276）。撤销与重新授权各自
//!    「先写 DB，再写 Redis」，两条链路交错时 Redis 的写入顺序可以与 DB 的提交
//!    顺序相反；迟到的撤销写入会留下与 `revoked_at IS NULL` 矛盾的标记，
//!    而读路径命中缓存直接短路，refresh / userinfo 被持续拒绝。
//!
//! 需要 PostgreSQL 和 Redis：连接串取自 `DATABASE_URL` / `REDIS_URL`，
//! 与 `tests/integration_storage.rs` 保持一致。

#[path = "support/db_isolation.rs"]
mod db_isolation;

use std::env;

use chenxing_auth::{
    clients::{
        domain::ValidatedClientRegistration,
        repository::{self as client_repository, ClientCredential},
    },
    consents::ConsentService,
    oauth::revocation::TokenRevocationStore,
    users::{
        credentials::hash_password, domain::ValidatedRegistration, email::EmailAddress,
        repository as user_repository,
    },
};
use redis::AsyncCommands;
use uuid::Uuid;

/// 测试夹具的邮箱构造。
///
/// `ValidatedRegistration.email` 是 `EmailAddress`（Issue #302），构造它必须经过
/// 唯一的规范化入口——夹具也不例外，否则测试会绕开被测的那条规则。
fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("consent_revocation_durability", &database_url).await
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
            email: email_address(format!("consent-{suffix}@example.com")),
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
            .is_some()
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

    // 按生产路径撤销：先写权威库，再带着这次撤销的版本号失效缓存
    let revoked_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent")
        .expect("revoke produces a state version");
    assert!(
        revocations
            .revoke_consent(&user_key, &client_id, revoked_version)
            .await
            .expect("cache revocation")
    );
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("check after revoke")
    );

    // 模拟 Redis 丢数据：只删掉这一对的缓存键，等价于 FLUSH / 无持久化重启 /
    // 故障转移到落后副本的效果，但不影响并发执行的其他测试。
    revocations
        .forget_consent_cache(&user_key, &client_id)
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
    let cached: Option<String> = connection
        .get(consent_cache_key(&user_key, &client_id))
        .await
        .expect("read cache key");
    assert_eq!(
        cached.as_deref(),
        Some(format!("{revoked_version}:r").as_str()),
        "authoritative lookup must back-fill the cache with the DB state version"
    );
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
    let revoked_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent")
        .expect("revoke produces a state version");
    revocations
        .revoke_consent(&user_key, &client_id, revoked_version)
        .await
        .expect("cache revocation");
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("cached revocation")
    );

    revocations
        .forget_consent_cache(&user_key, &client_id)
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
    let first_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("first revoke")
        .expect("first revoke produces a version");
    let first = revoked_at(&pool, user_id, &client_id)
        .await
        .expect("first revoked_at");

    // 第二次没有生效授权可撤销 -> None，handler 幂等返回 204
    assert_eq!(
        consents
            .revoke_for_user(user_id, &client_id)
            .await
            .expect("second revoke"),
        None
    );
    // 首次撤销时刻作为审计证据必须稳定，不被重复请求刷新
    assert_eq!(revoked_at(&pool, user_id, &client_id).await, Some(first));
    // 版本号同样不被消耗：否则重复撤销会白白抬高版本，让后续合法的重新授权
    // 写入被围栏挡住。
    assert_eq!(
        state_version(&pool, user_id, &client_id).await,
        Some(first_version)
    );
}

// ========== Issue #276：DB → Redis 双写交错 ==========

/// 核心回归：撤销的 Redis 写入迟于重新授权时，缓存不得拒绝 refresh / userinfo。
///
/// 复现的时序（每一步都是真实生产路径的一部分）：
///
/// ```text
/// 1. 撤销   : soft_revoke            → DB v2, revoked_at = now()
/// 2. 重新授权: upsert_consent         → DB v3, revoked_at IS NULL
/// 3. 重新授权: refresh_consent_cache  → 缓存写入 v3 已授权围栏
/// 4. 撤销   : revoke_consent(v2)      → 迟到，必须被围栏拒绝
/// ```
///
/// 修复前第 4 步用裸 `SET` 覆盖缓存，之后 `is_consent_revoked` 命中即返回
/// 「已撤销」并短路，refresh 与 userinfo 在 `revoked_at IS NULL` 的情况下
/// 被持续拒绝，直到 180 天的键 TTL 到期。
#[tokio::test]
async fn late_revocation_cache_write_cannot_deny_a_reauthorized_consent() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let revocations = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("initial grant");

    // 第 1 步：撤销的权威写入完成，但它的 Redis 写入被推迟（网络抖动 / 调度）
    let revoked_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent")
        .expect("revoke produces a state version");

    // 第 2 步 + 第 3 步：用户重新授权，授权码签发路径同步缓存围栏
    let reauthorized_version = consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("re-authorize");
    assert!(reauthorized_version > revoked_version);
    revocations
        .refresh_consent_cache(&user_key, &client_id)
        .await
        .expect("sync consent cache after re-authorization");

    // 第 4 步：迟到的撤销写入落地。它携带的版本号比缓存里的旧，必须被拒绝。
    assert!(
        !revocations
            .revoke_consent(&user_key, &client_id, revoked_version)
            .await
            .expect("late revocation cache write"),
        "a revocation write older than the cached state must be rejected"
    );

    // 权威库的事实：已重新授权
    assert!(
        revoked_at(&pool, user_id, &client_id).await.is_none(),
        "database must show the consent as re-authorized"
    );
    // refresh（refresh_use_case）和 userinfo 的第一道闸门：撤销判定
    assert!(
        !revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("consent revocation check"),
        "stale cache must not deny a consent whose revoked_at IS NULL"
    );
    // 第二道闸门：scope 判定（权威库直查，缓存无法替它放行）
    assert!(
        consents
            .has_scopes(user_id, &client_id, &["openid".to_owned()])
            .await
            .expect("scope check"),
        "re-authorized consent must satisfy the scope gate"
    );
}

/// 反向交错：迟到的撤销写入先落盘，随后的重新授权同步必须纠正它。
///
/// 这条覆盖「重新授权的缓存同步发生在撤销写入之后」的顺序。围栏在这里不起作用
/// （缓存里的版本更旧），纠正来自 `refresh_consent_cache` 按权威状态重写缓存。
#[tokio::test]
async fn cache_sync_corrects_a_revocation_marker_written_before_re_authorization() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let revocations = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("initial grant");
    let revoked_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent")
        .expect("revoke produces a state version");
    assert!(
        revocations
            .revoke_consent(&user_key, &client_id, revoked_version)
            .await
            .expect("cache revocation")
    );
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("revoked before re-authorization")
    );

    // 重新授权：先写权威库，再同步缓存
    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("re-authorize");
    revocations
        .refresh_consent_cache(&user_key, &client_id)
        .await
        .expect("sync consent cache after re-authorization");

    assert!(
        !revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("consent revocation check"),
        "cache sync must clear a revocation marker the database no longer agrees with"
    );
    assert!(
        consents
            .has_scopes(user_id, &client_id, &["openid".to_owned()])
            .await
            .expect("scope check")
    );
}

/// 围栏不得延迟真正的新撤销：重新授权之后再撤销，必须立即生效。
///
/// 这是 #276 修复的安全边界。如果围栏做成「已授权的缓存值在 TTL 内一律优先」，
/// 撤销就会被推迟到围栏过期，等于用一个 bug 换另一个更严重的 bug。
#[tokio::test]
async fn a_newer_revocation_after_re_authorization_takes_effect_immediately() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let revocations = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("initial grant");
    consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("first revoke");
    consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("re-authorize");
    revocations
        .refresh_consent_cache(&user_key, &client_id)
        .await
        .expect("sync consent cache");

    // 用户再次撤销：版本号比围栏更高，条件写必须接受
    let newest_version = consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("second revoke")
        .expect("second revoke produces a state version");
    assert!(
        revocations
            .revoke_consent(&user_key, &client_id, newest_version)
            .await
            .expect("fresh revocation cache write"),
        "a revocation newer than the cached fence must be accepted"
    );

    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("consent revocation check"),
        "a fresh revocation must take effect immediately, not after the fence expires"
    );
    assert!(
        !consents
            .has_scopes(user_id, &client_id, &["openid".to_owned()])
            .await
            .expect("scope check")
    );
}

/// 缓存里的「已授权」围栏不得替数据库放行已撤销的同意。
///
/// 围栏只用于挡住陈旧写入。若 Redis 在撤销时不可用（写入丢失），围栏仍在，
/// 但读路径不会把它当作放行凭据：它会回源 PostgreSQL 并得到「已撤销」。
#[tokio::test]
async fn an_active_fence_never_grants_access_to_a_revoked_consent() {
    let pool = database().await;
    let consents = ConsentService::new(pool.clone());
    let revocations = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    let user_key = user_id.to_string();

    let granted_version = consents
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("initial grant");
    assert!(
        revocations
            .activate_consent(&user_key, &client_id, granted_version)
            .await
            .expect("record active fence")
    );

    // 撤销只写权威库；模拟 Redis 写入完全失败（缓存仍是「已授权」围栏）
    consents
        .revoke_for_user(user_id, &client_id)
        .await
        .expect("revoke consent")
        .expect("revoke produces a state version");

    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("consent revocation check"),
        "the read path must fall back to the database instead of trusting the active fence"
    );
    // 回源后缓存被纠正为「已撤销」，后续判定不必再查库
    assert!(
        revocations
            .is_consent_revoked(&user_key, &client_id)
            .await
            .expect("second consent revocation check")
    );
}

/// 复算 `ConsentStateCache` 的缓存键，用于直接断言缓存回填。
///
/// 与 `consent_cache.rs` 的 `key` 保持一致：SHA-256("user:client") 的
/// URL-safe base64（无填充）。键格式属于内部实现，这里复制一份而不是暴露出来，
/// 以免把缓存布局变成对外契约。
fn consent_cache_key(user_id: &str, client_id: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(format!("{user_id}:{client_id}").as_bytes());
    format!(
        "chenxing:oauth:consent-state:{}",
        URL_SAFE_NO_PAD.encode(digest)
    )
}

/// 直接读 `state_version`，验证版本号真的随状态跃迁推进。
async fn state_version(
    pool: &chenxing_auth::sqlx::PgPool,
    user_id: chenxing_auth::users::domain::UserId,
    client_id: &str,
) -> Option<i64> {
    chenxing_auth::sqlx::query_as::<_, (i64,)>(
        "SELECT c.state_version FROM user_consents c
         JOIN oauth_clients oc ON oc.id = c.client_id
         WHERE c.user_id = $1 AND oc.client_id = $2",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .expect("read state_version")
    .map(|(value,)| value)
}
