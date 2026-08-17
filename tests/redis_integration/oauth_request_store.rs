use chenxing_auth::{
    oauth::{
        consent::PendingAuthorization,
        request_store::{AuthorizationRequestStore, MAX_PENDING_REQUESTS_PER_CLIENT},
    },
    redis_keyspace::RedisKeyspace,
};
use redis::AsyncCommands;

struct StoreHarness {
    store: AuthorizationRequestStore,
    keyspace: RedisKeyspace,
}

fn store() -> StoreHarness {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let keyspace = RedisKeyspace::new(&format!("pending-store-{}", uuid::Uuid::new_v4().simple()))
        .expect("test Redis namespace");
    StoreHarness {
        store: AuthorizationRequestStore::with_keyspace(
            redis::Client::open(url).expect("Redis URL"),
            keyspace.clone(),
        ),
        keyspace,
    }
}

fn request_key(keyspace: &RedisKeyspace, request_id: &str) -> String {
    keyspace.key(&format!("chenxing:oauth:request:{request_id}"))
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
        issuer_generation: None,
        cas_revision: 0,
    }
}

#[tokio::test]
async fn pending_creation_enforces_per_client_capacity() {
    let StoreHarness { store, .. } = store();
    let client_id = format!("pending-capacity-{}", uuid::Uuid::new_v4().simple());
    for index in 0..MAX_PENDING_REQUESTS_PER_CLIENT {
        let request = pending(
            format!("request-{}-{index}", uuid::Uuid::new_v4().simple()),
            &client_id,
        );
        assert!(store.save_limited(&request).await.expect("save pending"));
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }
    let requests: Vec<_> = (0..MAX_PENDING_REQUESTS_PER_CLIENT)
        .map(|index| pending(format!("request-full-{index}"), &client_id))
        .collect();
    for request in &requests {
        assert!(store.save_limited(request).await.expect("save pending"));
    }
    let rejected = pending(
        format!("request-over-capacity-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(!store.save_limited(&rejected).await.expect("capacity check"));
    for request in requests {
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }
}

#[tokio::test]
async fn concurrent_pending_takes_have_one_winner() {
    let StoreHarness { store, .. } = store();
    let request = pending(
        format!("pending-take-{}", uuid::Uuid::new_v4().simple()),
        &format!("pending-take-client-{}", uuid::Uuid::new_v4().simple()),
    );
    store.save(&request).await.expect("save pending");
    let first_store = store.clone();
    let second_store = store.clone();
    let (first, second) = tokio::join!(
        first_store.take_if_matches(&request.request_id, &request),
        second_store.take_if_matches(&request.request_id, &request),
    );
    let winners = [
        first.expect("first take").is_some(),
        second.expect("second take").is_some(),
    ]
    .into_iter()
    .filter(|won| *won)
    .count();
    assert_eq!(winners, 1);
}

#[tokio::test]
async fn future_fields_do_not_break_pending_compare_and_swap() {
    let StoreHarness { store, keyspace } = store();
    let request = pending(
        format!("pending-future-{}", uuid::Uuid::new_v4().simple()),
        &format!("pending-future-client-{}", uuid::Uuid::new_v4().simple()),
    );
    store.save(&request).await.expect("save pending");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let key = request_key(&keyspace, &request.request_id);
    let payload: String = connection.get(&key).await.expect("stored pending JSON");
    let mut json: serde_json::Value = serde_json::from_str(&payload).expect("parse pending");
    json["future_field"] = serde_json::json!({"version": 2});
    let _: () = connection
        .set_ex(
            &key,
            serde_json::to_string(&json).expect("encode pending"),
            60,
        )
        .await
        .expect("inject future pending field");

    let mut replacement = request.clone();
    replacement.session_token_hash = Some("replacement-session".to_owned());
    assert!(
        store
            .replace_if_matches(&request.request_id, &request, &replacement)
            .await
            .expect("replace pending with future field")
    );

    let replaced = store
        .find(&request.request_id)
        .await
        .expect("find replaced pending")
        .expect("replaced pending");
    assert_eq!(replaced.cas_revision, 1);

    let replaced_payload: String = connection.get(&key).await.expect("replaced pending JSON");
    let mut replaced_json: serde_json::Value =
        serde_json::from_str(&replaced_payload).expect("parse replaced pending");
    replaced_json["another_future_field"] = serde_json::json!(true);
    let _: () = connection
        .set_ex(
            &key,
            serde_json::to_string(&replaced_json).expect("encode replaced pending"),
            60,
        )
        .await
        .expect("inject second future pending field");
    assert!(
        store
            .take_if_matches(&request.request_id, &replaced)
            .await
            .expect("take pending with future field")
            .is_some()
    );
}

#[tokio::test]
async fn consuming_pending_releases_capacity_once() {
    let StoreHarness { store, .. } = store();
    let client_id = format!("pending-release-{}", uuid::Uuid::new_v4().simple());
    let requests: Vec<_> = (0..MAX_PENDING_REQUESTS_PER_CLIENT)
        .map(|index| pending(format!("pending-release-{index}"), &client_id))
        .collect();
    for request in &requests {
        assert!(store.save_limited(request).await.expect("save pending"));
    }
    let consumed = store
        .take_if_matches(&requests[0].request_id, &requests[0])
        .await
        .expect("consume pending");
    assert!(consumed.is_some());
    assert!(
        store
            .take_if_matches(&requests[0].request_id, &requests[0])
            .await
            .expect("repeat pending consume")
            .is_none()
    );

    let replacement = pending(
        format!(
            "pending-release-replacement-{}",
            uuid::Uuid::new_v4().simple()
        ),
        &client_id,
    );
    assert!(
        store
            .save_limited(&replacement)
            .await
            .expect("reuse released capacity")
    );
    let rejected = pending(
        format!("pending-release-rejected-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(!store.save_limited(&rejected).await.expect("capacity check"));
    for request in requests.into_iter().skip(1) {
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }
    store
        .take(&replacement.request_id)
        .await
        .expect("cleanup replacement request");
}

#[tokio::test]
async fn expired_pending_request_releases_capacity_when_processed() {
    let StoreHarness { store, keyspace } = store();
    let client_id = format!("pending-expiry-{}", uuid::Uuid::new_v4().simple());
    let expired = pending(
        format!("pending-expired-{}", uuid::Uuid::new_v4().simple()),
        &client_id,
    );
    assert!(store.save_limited(&expired).await.expect("save pending"));
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: bool = connection
        .expire(request_key(&keyspace, &expired.request_id), 0)
        .await
        .expect("expire pending request");
    assert!(
        store
            .take(&expired.request_id)
            .await
            .expect("process expired request")
            .is_none()
    );

    let replacement = pending(
        format!(
            "pending-expiry-replacement-{}",
            uuid::Uuid::new_v4().simple()
        ),
        &client_id,
    );
    assert!(
        store
            .save_limited(&replacement)
            .await
            .expect("reuse expired capacity")
    );
    store
        .take(&replacement.request_id)
        .await
        .expect("cleanup replacement request");
}
