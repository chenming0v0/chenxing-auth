//! Access-token revocation durability (Issue #656).
//!
//! Failure scenario: a still-valid access token is revoked, then Redis loses
//! or evicts its revocation marker. JWT validation still succeeds, so UserInfo
//! must not treat a missing Redis marker as "not revoked".
//!
//! Needs PostgreSQL and Redis. Connection strings follow
//! `tests/consent_revocation_durability.rs`.

use crate::db_isolation;
use crate::oauth_flow;

use std::env;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    clients::{
        domain::ValidatedClientRegistration,
        repository::{self as client_repository, ClientCredential},
    },
    consents::ConsentService,
    oauth::{revocation::TokenRevocationStore, token::issue_access_token},
    users::{
        credentials::hash_password, domain::ValidatedRegistration, email::EmailAddress,
        repository as user_repository,
    },
};
use tower::ServiceExt;
use uuid::Uuid;

fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("access_token_revocation_durability", &database_url).await
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

fn unique_token() -> String {
    format!("access-token-{}", Uuid::new_v4().simple())
}

async fn seed_user_and_client(
    pool: &chenxing_auth::sqlx::PgPool,
) -> (chenxing_auth::users::domain::UserId, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let user = user_repository::insert_user(
        pool,
        ValidatedRegistration {
            username: format!("at-revoke-user-{suffix}"),
            email: email_address(format!("at-revoke-{suffix}@example.com")),
            password: "correct horse battery".to_owned(),
            display_name: Some("Access Token User".to_owned()),
        },
        hash_password("correct horse battery".to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert user");

    let client_id = format!("at-revoke-client-{suffix}");
    client_repository::insert_client(
        pool,
        ValidatedClientRegistration {
            client_name: "Access Token Client".to_owned(),
            redirect_uris: vec!["https://at-revoke.example/callback".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        },
        client_id.clone(),
        ClientCredential::SecretBasic("client-secret-hash".to_owned()),
    )
    .await
    .expect("insert client");

    (user.id, client_id)
}

async fn persisted_expiry(
    pool: &chenxing_auth::sqlx::PgPool,
    token: &str,
) -> Option<time::OffsetDateTime> {
    use sha2::{Digest, Sha256};

    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    chenxing_auth::sqlx::query_scalar::<_, time::OffsetDateTime>(
        "SELECT expires_at FROM revoked_access_tokens WHERE token_hash = $1",
    )
    .bind(digest.as_slice())
    .fetch_optional(pool)
    .await
    .expect("read revoked_access_tokens")
}

#[tokio::test]
async fn revoking_an_access_token_persists_a_durable_row() {
    let pool = database().await;
    let store = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let token = unique_token();

    store.revoke(&token, 60).await.expect("revoke token");
    assert!(
        persisted_expiry(&pool, &token).await.is_some(),
        "revocation must land in PostgreSQL so it survives Redis data loss"
    );
    assert!(
        store.is_revoked(&token).await.expect("check revoked"),
        "revoked token must be rejected while the durable row exists"
    );

    store.remove(&token).await.expect("cleanup");
}

#[tokio::test]
async fn access_token_revocation_survives_redis_marker_loss() {
    let pool = database().await;
    let store = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let token = unique_token();

    store.revoke(&token, 60).await.expect("revoke token");
    assert!(store.is_revoked(&token).await.expect("cached revocation"));

    store
        .forget_access_token_cache(&token)
        .await
        .expect("simulate redis eviction");

    assert!(
        store
            .is_revoked(&token)
            .await
            .expect("durable lookup after redis loss"),
        "a missing Redis marker must not resurrect a revoked access token"
    );

    store.remove(&token).await.expect("cleanup");
}

#[tokio::test]
async fn cache_only_store_loses_access_token_revocation_after_redis_flush() {
    let store = TokenRevocationStore::new(redis_client());
    let token = unique_token();

    store.revoke(&token, 60).await.expect("revoke token");
    assert!(store.is_revoked(&token).await.expect("cached revocation"));

    store
        .forget_access_token_cache(&token)
        .await
        .expect("simulate redis eviction");

    assert!(
        !store
            .is_revoked(&token)
            .await
            .expect("cache-only lookup after redis loss"),
        "cache-only mode has no authoritative fallback by design"
    );
}

#[tokio::test]
async fn durable_lookup_failure_fails_closed() {
    let pool = database().await;
    let store = TokenRevocationStore::new_with_pool(redis_client(), pool.clone());
    let token = unique_token();

    store.revoke(&token, 60).await.expect("revoke token");
    store
        .forget_access_token_cache(&token)
        .await
        .expect("force durable lookup");

    chenxing_auth::sqlx::query("DROP TABLE revoked_access_tokens")
        .execute(&pool)
        .await
        .expect("break durable lookup");

    store
        .is_revoked(&token)
        .await
        .expect_err("durable lookup failure must not be treated as not-revoked");
}

#[tokio::test]
async fn userinfo_rejects_a_revoked_token_after_redis_marker_loss() {
    let (state, pool, key_directory) =
        oauth_flow::test_state("access_token_revocation_durability").await;
    let router = api::router(state.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    ConsentService::new(pool.clone())
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");

    let issuer = state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
        .issuer()
        .as_str()
        .to_owned();
    let token = issue_access_token(
        &state.keys,
        &issuer,
        &user_id.to_string(),
        &client_id,
        &["openid".to_owned()],
        3600,
    )
    .expect("issue access token");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("userinfo before revoke"),
        )
        .await
        .expect("userinfo before revoke");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "fixture token must be accepted before revocation"
    );

    state
        .revocations
        .revoke(&token, 3600)
        .await
        .expect("revoke access token");
    state
        .revocations
        .forget_access_token_cache(&token)
        .await
        .expect("drop redis marker");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("userinfo after redis loss"),
        )
        .await
        .expect("userinfo after redis loss");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "UserInfo must still reject a revoked access token after Redis marker loss"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn userinfo_fails_closed_when_durable_revocation_lookup_fails() {
    let (state, pool, key_directory) =
        oauth_flow::test_state("access_token_revocation_durability").await;
    let router = api::router(state.clone());
    let (user_id, client_id) = seed_user_and_client(&pool).await;
    ConsentService::new(pool.clone())
        .save(user_id, &client_id, &["openid".to_owned()])
        .await
        .expect("save consent");

    let issuer = state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
        .issuer()
        .as_str()
        .to_owned();
    let token = issue_access_token(
        &state.keys,
        &issuer,
        &user_id.to_string(),
        &client_id,
        &["openid".to_owned()],
        3600,
    )
    .expect("issue access token");

    state
        .revocations
        .revoke(&token, 3600)
        .await
        .expect("revoke access token");
    state
        .revocations
        .forget_access_token_cache(&token)
        .await
        .expect("force durable lookup");

    chenxing_auth::sqlx::query("DROP TABLE revoked_access_tokens")
        .execute(&pool)
        .await
        .expect("break durable lookup");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("userinfo during lookup failure"),
        )
        .await
        .expect("userinfo during lookup failure");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "UserInfo must fail closed when durable revocation lookup fails"
    );
    let body = oauth_flow::json_body(response).await;
    assert_eq!(body["error"], "temporarily_unavailable");

    let _ = std::fs::remove_dir_all(key_directory);
}
