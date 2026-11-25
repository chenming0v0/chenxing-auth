use axum::http::StatusCode;
use chenxing_auth::auth_factors::repository;

use super::support::{Fixture, counter};
use crate::http;

const START: &str = "/api/v1/auth/passkeys/discoverable/start";
const FINISH: &str = "/api/v1/auth/passkeys/discoverable/finish";

async fn challenge(fixture: &Fixture) -> (String, String) {
    let response = fixture.post(START, serde_json::json!({}), "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    (
        body["challenge_id"]
            .as_str()
            .expect("discoverable challenge id")
            .to_owned(),
        body["options"]["publicKey"]["challenge"]
            .as_str()
            .expect("discoverable challenge")
            .to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discoverable_counter_cas_conflict_does_not_restore_the_old_challenge() {
    let fixture = Fixture::new(10, false).await;
    let (challenge_id, options) = challenge(&fixture).await;
    let before = fixture.stored().await;
    let mut transaction = fixture
        .app
        .database
        .begin()
        .await
        .expect("counter advance transaction");
    // 未提交的行锁让 finish 先用旧值验签，再在 CAS 写入时等待新的计数提交。
    chenxing_auth::sqlx::query(
        "UPDATE user_passkeys SET credential = $2, state_version = state_version + 1
         WHERE id = $1",
    )
    .bind(fixture.row_id)
    .bind(serde_json::to_value(fixture.authenticator.passkey(12)).expect("advanced Passkey"))
    .execute(&mut *transaction)
    .await
    .expect("advance the counter under a row lock");
    let assertion = fixture
        .authenticator
        .assertion(&options, fixture.user_id, 11);
    let router = fixture.app.router.clone();
    let challenge_for_request = challenge_id.clone();
    let finish = tokio::spawn(async move {
        http::post_json(
            &router,
            FINISH,
            serde_json::json!({
                "challenge_id": challenge_for_request,
                "credential": assertion
            }),
        )
        .await
    });
    let pending_key = format!("chenxing:auth:passkey-discoverable:{challenge_id}");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while fixture.pending(&pending_key).await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("finish must consume before the blocked CAS");
    transaction
        .commit()
        .await
        .expect("commit the newer counter");
    let response = finish.await.expect("discoverable finish task");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!http::set_cookies(&response).contains("chenxing_session="));
    assert_eq!(
        http::json_body(response).await["code"],
        "passkey_counter_conflict"
    );
    assert_eq!(fixture.session_count().await, 0);
    assert!(fixture.pending(&pending_key).await.is_none());
    let after = fixture.stored().await;
    assert_eq!(counter(after.passkey()), 12);
    assert_eq!(after.state_version, before.state_version + 1);

    let (fresh_id, fresh_options) = challenge(&fixture).await;
    assert_ne!(fresh_id, challenge_id);
    assert_ne!(fresh_options, options);
    let response = fixture
        .post(
            FINISH,
            serde_json::json!({
                "challenge_id": fresh_id,
                "credential": fixture.authenticator.assertion(&fresh_options, fixture.user_id, 13)
            }),
            "",
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(http::set_cookies(&response).contains("chenxing_session="));
    assert_eq!(fixture.session_count().await, 1);
    assert_eq!(counter(fixture.stored().await.passkey()), 13);
    assert_eq!(
        repository::count_passkeys(&fixture.app.database, fixture.user_id)
            .await
            .expect("credential remains registered"),
        1
    );
    fixture.app.cleanup().await;
}
