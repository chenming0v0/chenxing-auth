use std::sync::Arc;

use chenxing_auth::{
    oauth::providers::state_store::{
        EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS, EXTERNAL_LOGIN_STATE_TTL_SECONDS,
        ExternalLoginState, ExternalLoginStateStore, ExternalLoginStateStoreError,
    },
    redis_keyspace::RedisKeyspace,
};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn store_in_namespace(
    namespace: &str,
    source_rate_limit: i64,
    max_pending: i64,
) -> ExternalLoginStateStore {
    ExternalLoginStateStore::new_with_config_and_keyspace(
        redis::Client::open(redis_url()).expect("Redis URL"),
        EXTERNAL_LOGIN_STATE_TTL_SECONDS,
        EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
        source_rate_limit,
        max_pending,
        RedisKeyspace::new(namespace).expect("test Redis namespace"),
    )
}

fn store(source_rate_limit: i64, max_pending: i64) -> ExternalLoginStateStore {
    store_in_namespace(
        &format!("external-state-{}", Uuid::new_v4().simple()),
        source_rate_limit,
        max_pending,
    )
}

fn state(state: impl Into<String>, provider_slug: &str) -> ExternalLoginState {
    ExternalLoginState {
        state: state.into(),
        provider_slug: provider_slug.to_owned(),
        request_id: None,
        code_verifier: String::new(),
        purpose: "login".to_owned(),
        user_id: None,
        session_id: None,
        session_epoch: None,
    }
}

#[tokio::test]
async fn deployment_namespaces_isolate_external_login_states() {
    let suffix = Uuid::new_v4().simple().to_string();
    let first = store_in_namespace(&format!("external-state-a-{suffix}"), 10, 10);
    let second = store_in_namespace(&format!("external-state-b-{suffix}"), 10, 10);
    let state_id = format!("shared-state-{suffix}");
    let first_state = state(&state_id, "first-provider");
    let second_state = state(&state_id, "second-provider");

    first.save(&first_state).await.expect("save first state");
    second.save(&second_state).await.expect("save second state");

    assert_eq!(
        first.take(&state_id).await.expect("take first state"),
        Some(first_state)
    );
    assert_eq!(
        second.take(&state_id).await.expect("take second state"),
        Some(second_state)
    );
}

#[tokio::test]
async fn concurrent_admission_never_exceeds_pending_capacity() {
    let store = Arc::new(store(100, 4));
    let source_ip = "198.51.100.7";
    let mut tasks = Vec::new();
    for index in 0..32 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let state_id = format!("state-{index}");
            let candidate = state(&state_id, "example");
            let result = store.save_from_source(&candidate, source_ip).await;
            (state_id, result)
        }));
    }

    let mut outcomes = Vec::with_capacity(tasks.len());
    for task in tasks {
        outcomes.push(task.await.expect("admission task"));
    }
    assert_eq!(
        outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
        4
    );

    for (state_id, result) in outcomes {
        let stored = store.take(&state_id).await.expect("clean up state");
        match result {
            Ok(()) => assert!(stored.is_some(), "every admitted state must be stored"),
            Err(ExternalLoginStateStoreError::CapacityExceeded) => {
                assert!(stored.is_none(), "rejected states must not be created")
            }
            Err(error) => panic!("unexpected admission error: {error}"),
        }
    }
}

#[tokio::test]
async fn source_rate_limit_rejects_without_creating_an_extra_state() {
    let store = store(2, 10);
    let source_ip = "198.51.100.8";
    let admitted = [
        state("state-first", "example"),
        state("state-second", "example"),
    ];
    for state in &admitted {
        store
            .save_from_source(state, source_ip)
            .await
            .expect("state admission");
    }

    let rejected = state("state-third", "example");
    assert!(matches!(
        store.save_from_source(&rejected, source_ip).await,
        Err(ExternalLoginStateStoreError::RateLimited)
    ));
    assert!(
        store
            .take(&rejected.state)
            .await
            .expect("inspect rejected state")
            .is_none(),
        "rate-limited admission must not create a state payload"
    );

    for state in admitted {
        assert!(
            store
                .take(&state.state)
                .await
                .expect("clean up admitted state")
                .is_some()
        );
    }
}

#[tokio::test]
async fn purpose_and_provider_mismatch_preserve_state_until_valid_consumer() {
    let store = store(10, 10);
    let pending = ExternalLoginState {
        state: "binding-state".to_owned(),
        provider_slug: "provider-a".to_owned(),
        request_id: None,
        code_verifier: String::new(),
        purpose: "binding".to_owned(),
        user_id: Some(7),
        session_id: Some(9),
        session_epoch: Some(3),
    };
    store.save(&pending).await.expect("save binding state");

    assert_eq!(
        store
            .take_for_purpose_and_provider(&pending.state, "login", "provider-a")
            .await
            .expect("purpose check"),
        chenxing_auth::oauth::providers::state_store::ExternalLoginStateTake::Mismatch,
    );
    assert_eq!(
        store
            .take_for_purpose_and_provider(&pending.state, "binding", "provider-b")
            .await
            .expect("provider check"),
        chenxing_auth::oauth::providers::state_store::ExternalLoginStateTake::Mismatch,
    );
    assert_eq!(
        store
            .take_for_purpose_and_provider(&pending.state, "binding", "provider-a")
            .await
            .expect("consume binding state"),
        chenxing_auth::oauth::providers::state_store::ExternalLoginStateTake::Consumed(pending),
    );
    assert_eq!(
        store
            .take_for_purpose_and_provider("binding-state", "binding", "provider-a")
            .await
            .expect("replay check"),
        chenxing_auth::oauth::providers::state_store::ExternalLoginStateTake::MissingOrConsumed,
    );
}

#[tokio::test]
async fn concurrent_provider_aware_consumption_is_single_use() {
    let store = Arc::new(store(10, 10));
    let pending = state("single-use", "provider");
    store.save(&pending).await.expect("save state");
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            store
                .take_for_purpose_and_provider("single-use", "login", "provider")
                .await
                .expect("consume state")
        }));
    }
    let mut consumed = 0;
    for task in tasks {
        if matches!(
            task.await.expect("consumer task"),
            chenxing_auth::oauth::providers::state_store::ExternalLoginStateTake::Consumed(_)
        ) {
            consumed += 1;
        }
    }
    assert_eq!(consumed, 1);
}
