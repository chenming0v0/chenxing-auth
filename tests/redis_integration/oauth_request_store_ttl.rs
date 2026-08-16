use chenxing_auth::{
    oauth::{consent::PendingAuthorization, request_store::AuthorizationRequestStore},
    redis_keyspace::RedisKeyspace,
    settings::SecurityLimitsSetting,
};
use redis::AsyncCommands;

struct StoreHarness {
    store: AuthorizationRequestStore,
    keyspace: RedisKeyspace,
}

fn store() -> StoreHarness {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let keyspace = RedisKeyspace::new(&format!("pending-ttl-{}", uuid::Uuid::new_v4().simple()))
        .expect("test Redis namespace");
    StoreHarness {
        store: AuthorizationRequestStore::with_keyspace(
            redis::Client::open(url).expect("Redis URL"),
            keyspace.clone(),
        ),
        keyspace,
    }
}

fn pending(request_id: String, client_id: &str) -> PendingAuthorization {
    PendingAuthorization {
        request_id,
        client_id: client_id.to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "state".to_owned(),
        nonce: None,
        code_challenge: "challenge".to_owned(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: None,
        holder_hash: None,
        cas_revision: 0,
    }
}

fn request_key(keyspace: &RedisKeyspace, request_id: &str) -> String {
    keyspace.key(&format!("chenxing:oauth:request:{request_id}"))
}

fn client_index_key(keyspace: &RedisKeyspace, client_id: &str) -> String {
    keyspace.key(&format!(
        "chenxing:oauth:pending:client-requests:{client_id}"
    ))
}

fn client_count_key(keyspace: &RedisKeyspace, client_id: &str) -> String {
    keyspace.key(&format!("chenxing:oauth:pending:client:{client_id}"))
}

fn global_index_key(keyspace: &RedisKeyspace) -> String {
    keyspace.key("chenxing:oauth:pending:index")
}

fn global_count_key(keyspace: &RedisKeyspace) -> String {
    keyspace.key("chenxing:oauth:pending:global")
}

fn global_expiry_key(keyspace: &RedisKeyspace) -> String {
    keyspace.key("chenxing:oauth:pending:expiry")
}

fn tight_pending_limits() -> SecurityLimitsSetting {
    SecurityLimitsSetting {
        max_pending_requests_per_client: 2,
        max_pending_requests_global: 2,
        pending_request_ttl_seconds: 600,
        ..SecurityLimitsSetting::default()
    }
}

async fn redis_connection() -> redis::aio::MultiplexedConnection {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(redis_url)
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection")
}

async fn assert_shared_ttl_covers_long_lived(
    connection: &mut redis::aio::MultiplexedConnection,
    keys: &[String],
) {
    for key in keys {
        let ttl: i64 = connection.ttl(key).await.expect("shared index TTL");
        assert!(
            ttl > 500,
            "shared key {key} TTL must stay near the long-lived request, got {ttl}"
        );
    }
}

#[tokio::test]
async fn restoring_near_expiry_request_does_not_shrink_shared_index_ttl() {
    let StoreHarness { store, keyspace } = store();
    let mut connection = redis_connection().await;
    let limits = tight_pending_limits();
    let client_id = format!("pending-ttl-{}", uuid::Uuid::new_v4().simple());
    let other_client = format!("pending-ttl-other-{}", uuid::Uuid::new_v4().simple());

    let long_lived = pending(
        format!("pending-ttl-long-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(
        store
            .save_limited_with_limits(&long_lived, &limits)
            .await
            .expect("save long-lived pending")
    );

    let shared_keys = [
        client_index_key(&keyspace, &client_id),
        client_count_key(&keyspace, &client_id),
        global_index_key(&keyspace),
        global_count_key(&keyspace),
        global_expiry_key(&keyspace),
    ];
    assert_shared_ttl_covers_long_lived(&mut connection, &shared_keys).await;

    let near_expiry = pending(
        format!("pending-ttl-short-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(
        store
            .save_limited_with_limits_and_ttl(&near_expiry, &limits, Some(1_500))
            .await
            .expect("restore near-expiry pending")
    );
    assert_shared_ttl_covers_long_lived(&mut connection, &shared_keys).await;

    assert!(
        store
            .find(&long_lived.request_id)
            .await
            .expect("find long-lived")
            .is_some()
    );
    assert!(
        !store
            .save_limited_with_limits(
                &pending(
                    format!("pending-ttl-overflow-{}", uuid::Uuid::new_v4().simple()),
                    &client_id
                ),
                &limits
            )
            .await
            .expect("client cap while both live")
    );

    let _: bool = connection
        .expire(request_key(&keyspace, &near_expiry.request_id), 0)
        .await
        .expect("expire restored pending");
    assert!(
        store
            .find(&near_expiry.request_id)
            .await
            .expect("find expired restore")
            .is_none()
    );

    let replacement = pending(
        format!("pending-ttl-replacement-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(
        store
            .save_limited_with_limits(&replacement, &limits)
            .await
            .expect("reuse expired restore slot")
    );
    assert!(
        store
            .find(&long_lived.request_id)
            .await
            .expect("long-lived still counted")
            .is_some()
    );
    assert!(
        !store
            .save_limited_with_limits(
                &pending(
                    format!("pending-ttl-client-cap-{}", uuid::Uuid::new_v4().simple()),
                    &client_id
                ),
                &limits
            )
            .await
            .expect("client cap after restore expiry")
    );
    assert!(
        !store
            .save_limited_with_limits(
                &pending(
                    format!("pending-ttl-global-cap-{}", uuid::Uuid::new_v4().simple()),
                    &other_client
                ),
                &limits
            )
            .await
            .expect("global cap after restore expiry")
    );

    store
        .take(&long_lived.request_id)
        .await
        .expect("cleanup long-lived request");
    store
        .take(&replacement.request_id)
        .await
        .expect("cleanup replacement request");
}
