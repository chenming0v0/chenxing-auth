//! Issue #734：旧 challenge 的计数冲突不签会话，新 challenge 可恢复认证。

#[path = "passkey_counter/discoverable.rs"]
mod discoverable;
#[path = "passkey_counter/re_registration.rs"]
mod re_registration;
#[path = "passkey_counter/support.rs"]
mod support;

use axum::http::StatusCode;
use chenxing_auth::auth_factors::repository::{self, PasskeyPersistOutcome};

use crate::http;
use support::{FINISH, Fixture, counter};

#[tokio::test]
async fn stale_challenge_requires_a_fresh_challenge_and_then_recovers() {
    let fixture = Fixture::new(10, false).await;
    let ticket = fixture.ticket().await;
    let challenge = fixture.challenge(&ticket.2).await;
    let before = fixture.stored().await;
    assert_eq!(
        repository::persist_passkey_authentication(
            &fixture.app.database,
            fixture.user_id,
            fixture.row_id,
            before.cred_id(),
            &fixture.authenticator.result(12, true),
        )
        .await
        .expect("another login advances the counter"),
        PasskeyPersistOutcome::Applied
    );

    let response = fixture
        .post(
            FINISH,
            serde_json::json!({
                "credential": fixture.authenticator.assertion(&challenge, fixture.user_id, 11)
            }),
            &ticket.2,
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!http::set_cookies(&response).contains("chenxing_session="));
    assert_eq!(
        http::json_body(response).await["code"],
        "passkey_counter_conflict"
    );
    assert_eq!(fixture.session_count().await, 0);
    assert_eq!(
        fixture
            .app
            .state
            .factors
            .user_id_for_ticket(&ticket.0, &ticket.1)
            .await
            .expect("restored login ticket"),
        Some(fixture.user_id)
    );
    assert!(
        fixture
            .pending(&format!(
                "chenxing:auth:passkey-authentication:{}",
                ticket.0
            ))
            .await
            .is_none(),
        "the old reservation must not be reused"
    );
    let after = fixture.stored().await;
    assert_eq!(counter(after.passkey()), 12);
    assert_eq!(after.state_version, before.state_version + 1);
    let failures: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'mfa_failure' AND actor_user_id = $1",
    )
    .bind(fixture.user_id)
    .fetch_one(&fixture.app.database)
    .await
    .expect("factor failures");
    assert_eq!(
        failures, 0,
        "a counter race is not a failed credential attempt"
    );

    let fresh = fixture.challenge(&ticket.2).await;
    assert_ne!(fresh, challenge);
    let response = fixture
        .post(
            FINISH,
            serde_json::json!({
                "credential": fixture.authenticator.assertion(&fresh, fixture.user_id, 13)
            }),
            &ticket.2,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(http::set_cookies(&response).contains("chenxing_session="));
    assert_eq!(fixture.session_count().await, 1);
    assert_eq!(counter(fixture.stored().await.passkey()), 13);
    fixture.app.cleanup().await;
}

#[tokio::test]
async fn zero_counter_synchronised_passkey_can_authenticate_repeatedly() {
    let fixture = Fixture::new(0, true).await;
    for _ in 0..2 {
        let ticket = fixture.ticket().await;
        let challenge = fixture.challenge(&ticket.2).await;
        let response = fixture
            .post(
                FINISH,
                serde_json::json!({
                    "credential": fixture.authenticator.assertion(&challenge, fixture.user_id, 0)
                }),
                &ticket.2,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(http::set_cookies(&response).contains("chenxing_session="));
    }
    assert_eq!(fixture.session_count().await, 2);
    assert_eq!(counter(fixture.stored().await.passkey()), 0);
    fixture.app.cleanup().await;
}

#[tokio::test]
async fn latest_nonzero_counter_is_checked_even_without_the_old_update_hint() {
    let fixture = Fixture::new(7, false).await;
    let before = fixture.stored().await;
    for needs_update in [false, true] {
        for asserted_counter in [0, 6, 7] {
            assert_eq!(
                repository::persist_passkey_authentication(
                    &fixture.app.database,
                    fixture.user_id,
                    fixture.row_id,
                    before.cred_id(),
                    &fixture.authenticator.result(asserted_counter, needs_update),
                )
                .await
                .expect("persist a non-increasing counter"),
                PasskeyPersistOutcome::CounterConflict,
                "counter={asserted_counter}, needs_update={needs_update}"
            );
        }
    }
    let after = fixture.stored().await;
    assert_eq!(counter(after.passkey()), 7);
    assert_eq!(after.state_version, before.state_version);
    assert_eq!(fixture.session_count().await, 0);
    assert_eq!(
        repository::persist_passkey_authentication(
            &fixture.app.database,
            fixture.user_id,
            fixture.row_id,
            before.cred_id(),
            &fixture.authenticator.result(8, true),
        )
        .await
        .expect("persist a newer counter"),
        PasskeyPersistOutcome::Applied
    );
    assert_eq!(counter(fixture.stored().await.passkey()), 8);
    fixture.app.cleanup().await;
}
