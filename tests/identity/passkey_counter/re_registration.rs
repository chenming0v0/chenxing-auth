use axum::http::StatusCode;
use chenxing_auth::auth_factors::repository;

use super::support::{FINISH, Fixture, counter};
use crate::http;

#[tokio::test]
async fn old_challenge_cannot_update_a_re_registered_row_and_retry_binds_the_new_row() {
    let fixture = Fixture::new(10, false).await;
    let before = fixture.stored().await;
    let ticket = fixture.ticket().await;
    let challenge = fixture.challenge(&ticket.2).await;
    chenxing_auth::sqlx::query("DELETE FROM user_passkeys WHERE id = $1")
        .bind(fixture.row_id)
        .execute(&fixture.app.database)
        .await
        .expect("delete the challenge-bound credential row");
    assert_eq!(
        repository::insert_passkey_if_empty(
            &fixture.app.database,
            fixture.user_id,
            0,
            before.cred_id(),
            &fixture.authenticator.passkey(0),
        )
        .await
        .expect("re-register the same credential id"),
        repository::PasskeyPersistenceResult::Stored
    );
    let replacement =
        repository::list_passkeys_with_versions(&fixture.app.database, fixture.user_id)
            .await
            .expect("replacement Passkey")
            .pop()
            .expect("replacement row");
    assert_ne!(replacement.id, before.id);

    let response = fixture
        .post(
            FINISH,
            serde_json::json!({
                "credential": fixture.authenticator.assertion(&challenge, fixture.user_id, 11)
            }),
            &ticket.2,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(http::json_body(response).await["code"], "invalid_factor");
    assert_eq!(fixture.session_count().await, 0);
    let untouched =
        repository::find_passkey_row(&fixture.app.database, fixture.user_id, replacement.id)
            .await
            .expect("reload replacement")
            .expect("replacement remains registered");
    assert_eq!(counter(untouched.passkey()), 0);
    assert_eq!(untouched.state_version, replacement.state_version);
    assert!(
        fixture
            .pending(&format!(
                "chenxing:auth:passkey-authentication:{}",
                ticket.0
            ))
            .await
            .is_none()
    );

    let fresh = fixture.challenge(&ticket.2).await;
    assert_ne!(fresh, challenge);
    let response = fixture
        .post(
            FINISH,
            serde_json::json!({
                "credential": fixture.authenticator.assertion(&fresh, fixture.user_id, 12)
            }),
            &ticket.2,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(http::set_cookies(&response).contains("chenxing_session="));
    assert_eq!(fixture.session_count().await, 1);
    let after =
        repository::find_passkey_row(&fixture.app.database, fixture.user_id, replacement.id)
            .await
            .expect("reload authenticated replacement")
            .expect("replacement row");
    assert_eq!(counter(after.passkey()), 12);
    assert_eq!(after.state_version, replacement.state_version + 1);
    fixture.app.cleanup().await;
}
