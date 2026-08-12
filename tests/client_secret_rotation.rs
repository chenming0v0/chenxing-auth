#[path = "support/db_isolation.rs"]
mod db_isolation;

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
    // Simulate a Client row that existed before migration 0026. Its unversioned
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
