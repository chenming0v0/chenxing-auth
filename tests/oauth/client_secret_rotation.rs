use crate::db_isolation;

use chenxing_auth::clients::{
    domain::ValidatedClientRegistration,
    repository::{self, ClientCredential},
};
use std::env;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections("client_secret_rotation", &database_url, 2)
        .await
}

#[tokio::test]
async fn concurrent_secret_writes_have_one_compare_and_swap_winner() {
    let pool = database().await;
    let client_id = format!("cx_cas_{}", Uuid::new_v4().simple());
    let client = repository::insert_client(
        &pool,
        ValidatedClientRegistration {
            client_name: "CAS test client".to_owned(),
            redirect_uris: vec!["https://cas.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            logo_uri: None,
            client_uri: None,
            description: None,
        },
        client_id.clone(),
        ClientCredential::SecretBasic("initial-hash".to_owned()),
    )
    .await
    .expect("insert client");
    assert!(
        !repository::find_client_credentials(&pool, &client_id)
            .await
            .expect("read new client credentials")
            .expect("new client credentials")
            .allow_legacy_refresh_tokens,
        "new Clients must never open the legacy token compatibility window"
    );
    // Simulate an explicitly enabled legacy compatibility window. Unversioned
    // Refresh Tokens remain compatible only until the next Secret rotation.
    chenxing_auth::sqlx::query(
        "UPDATE oauth_clients SET allow_legacy_refresh_tokens = TRUE WHERE client_id = $1",
    )
    .bind(&client_id)
    .execute(&pool)
    .await
    .expect("open legacy refresh compatibility window");
    let version = repository::find_client_secret_version(&pool, None, &client_id)
        .await
        .expect("read client secret version")
        .expect("client secret version");

    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first = repository::update_client_secret_if_version(
        &first_pool,
        None,
        &client_id,
        version,
        "first-hash",
    );
    let second = repository::update_client_secret_if_version(
        &second_pool,
        None,
        &client_id,
        version,
        "second-hash",
    );
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first CAS update");
    let second = second.expect("second CAS update");
    assert_ne!(first, second, "exactly one stale writer must win");

    let credentials = repository::find_client_credentials(&pool, &client_id)
        .await
        .expect("read rotated credentials")
        .expect("rotated credentials");
    assert_eq!(
        credentials.client_secret_hash.as_deref(),
        Some(if first { "first-hash" } else { "second-hash" })
    );
    assert!(
        !credentials.allow_legacy_refresh_tokens,
        "the winning rotation must permanently close the legacy token window"
    );
    assert_eq!(
        repository::find_client_secret_version(&pool, None, &client_id)
            .await
            .expect("read final client secret version"),
        Some(version + 1),
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client.id)
        .execute(&pool)
        .await
        .expect("cleanup client");
}

/// Issue #351：轮换路径必须与认证路径（`credentials::constant_time` 的
/// `policy_gate_ok`）一样把 `status = 'active'` 作为策略门，disabled Client
/// 不允许被轮换、更不允许拿到新 Secret。
///
/// 两道门都验证：
/// - 读门：`find_client_secret_version` 对 disabled Client 返回 `None`，
///   使服务层把它当作「不存在」拒绝（与 owner 越权、公开 Client 同语义）。
/// - CAS 门：即使调用方带着禁用前观察到的旧版本号强写（读后禁用的
///   TOCTOU 窗口），`update_client_secret_if_version` 也必须返回 `false`
///   且不产生任何副作用——hash 不变、版本不递增。
#[tokio::test]
async fn disabled_client_secret_rotation_is_rejected_without_side_effects() {
    let pool = database().await;
    let client_id = format!("cx_cas_disabled_{}", Uuid::new_v4().simple());
    let client = repository::insert_client(
        &pool,
        ValidatedClientRegistration {
            client_name: "disabled rotation test client".to_owned(),
            redirect_uris: vec!["https://disabled-rotation.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            logo_uri: None,
            client_uri: None,
            description: None,
        },
        client_id.clone(),
        ClientCredential::SecretBasic("initial-hash".to_owned()),
    )
    .await
    .expect("insert client");
    repository::set_client_status(&pool, None, &client_id, "disabled")
        .await
        .expect("disable client");

    assert_eq!(
        repository::find_client_secret_version(&pool, None, &client_id)
            .await
            .expect("read version of disabled client"),
        None,
        "a disabled client must not expose its secret version to the rotation read path"
    );

    let updated =
        repository::update_client_secret_if_version(&pool, None, &client_id, 0, "forged-hash")
            .await
            .expect("CAS update of disabled client");
    assert!(
        !updated,
        "a disabled client must never receive a fresh secret hash, even with a stale version"
    );

    let credentials = repository::find_client_credentials(&pool, &client_id)
        .await
        .expect("read disabled client credentials")
        .expect("disabled client credentials");
    assert_eq!(
        credentials.client_secret_hash.as_deref(),
        Some("initial-hash"),
        "the rejected rotation must not overwrite the stored hash"
    );
    assert_eq!(
        credentials.client_secret_version, 0,
        "the rejected rotation must not bump the secret version"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client.id)
        .execute(&pool)
        .await
        .expect("cleanup client");
}
