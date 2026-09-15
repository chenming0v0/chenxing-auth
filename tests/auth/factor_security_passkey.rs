use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chenxing_auth::auth_factors::{domain::FactorMethod, repository, store::LoginTicketStore};
use redis::AsyncCommands;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::http;

use super::factor_security_api::{
    ISSUER, PASSWORD, TestApp, csrf, redis_connection, registration_fixture, test_passkey,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_passkey_finish_persists_and_consumes_once() {
    let app = TestApp::new("factor_security_passkey_finish").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(start.status(), StatusCode::OK);
    let start_body = http::json_body(start).await;
    let enrollment_id = start_body["enrollment_id"].as_str().expect("enrollment id");
    let challenge = start_body["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("registration challenge");
    let credential = registration_fixture(challenge, ISSUER);
    let wrong_origin = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "credential": registration_fixture(challenge, "http://127.0.0.1:8080")
            }),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(wrong_origin.status(), StatusCode::UNAUTHORIZED);

    let second_login = app.login(&username, PASSWORD).await;
    let second_cookie = http::set_cookies(&second_login);
    let second_csrf = csrf(&second_cookie);
    let wrong_session = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            serde_json::json!({"enrollment_id": enrollment_id, "credential": credential}),
            None,
            Some((&second_cookie, &second_csrf)),
        )
        .await;
    assert_eq!(wrong_session.status(), StatusCode::BAD_REQUEST);

    let finish_body = serde_json::json!({
        "enrollment_id": enrollment_id,
        "credential": registration_fixture(challenge, ISSUER)
    });
    let (first_finish, second_finish) = tokio::join!(
        app.request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            finish_body.clone(),
            None,
            Some((&cookie, &csrf_token)),
        ),
        app.request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            finish_body,
            None,
            Some((&cookie, &csrf_token)),
        )
    );
    let statuses = [first_finish.status(), second_finish.status()];
    assert!(
        statuses.contains(&StatusCode::OK),
        "finish statuses: {statuses:?}"
    );
    assert!(
        statuses.contains(&StatusCode::BAD_REQUEST),
        "finish statuses: {statuses:?}"
    );
    assert_eq!(
        repository::count_passkeys(&app.database, user_id)
            .await
            .expect("Passkey count"),
        1
    );

    let (_, other_username, _) = app.create_user().await;
    let other_login = app.login(&other_username, PASSWORD).await;
    let other_cookie = http::set_cookies(&other_login);
    let other_csrf = csrf(&other_cookie);
    let other_start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&other_cookie, &other_csrf)),
        )
        .await;
    assert_eq!(other_start.status(), StatusCode::OK);
    let other_start = http::json_body(other_start).await;
    let other_enrollment = other_start["enrollment_id"]
        .as_str()
        .expect("other enrollment id");
    let other_challenge = other_start["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("other registration challenge");
    let cross_user = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            serde_json::json!({
                "enrollment_id": other_enrollment,
                "credential": registration_fixture(other_challenge, ISSUER)
            }),
            None,
            Some((&other_cookie, &other_csrf)),
        )
        .await;
    assert_eq!(cross_user.status(), StatusCode::CONFLICT);

    let factor_login = app.login(&username, PASSWORD).await;
    assert_eq!(factor_login.status(), StatusCode::OK);
    let factor_body = http::json_body(factor_login).await;
    assert!(factor_body["expires_at"].as_str().is_some());
    assert!(factor_body.get("status").is_none());
}
#[tokio::test]
async fn authenticated_passkey_finish_rejects_wrong_rp_id() {
    let origin = "https://login.example.com";
    let app = TestApp::new_with_webauthn(
        "factor_security_passkey_wrong_rp",
        "login.example.com",
        origin,
    )
    .await;
    let (_, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    let start = http::json_body(start).await;
    let response = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/finish",
            serde_json::json!({
                "enrollment_id": start["enrollment_id"],
                "credential": registration_fixture(
                    start["options"]["publicKey"]["challenge"]
                        .as_str()
                        .expect("registration challenge"),
                    origin,
                )
            }),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkey_pending_is_owner_bound_and_consumed_once() {
    let app = TestApp::new("factor_security_passkey_consume").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    let start_body = http::json_body(start).await;
    let enrollment_id = start_body["enrollment_id"]
        .as_str()
        .expect("enrollment id")
        .to_owned();
    let session_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("session id");
    let key = format!("chenxing:auth:session-enrollment:{user_id}:passkey");
    let store =
        LoginTicketStore::new(redis::Client::open(app.redis_url.as_str()).expect("Redis client"));
    assert!(
        store
            .take_session_enrollment_if_owner::<Value>(
                &key,
                user_id,
                session_id + 1,
                0,
                FactorMethod::Passkey,
                &enrollment_id,
            )
            .await
            .expect("wrong session consume")
            .is_none()
    );
    let tasks = (0..2)
        .map(|_| {
            let store = store.clone();
            let key = key.clone();
            let enrollment_id = enrollment_id.clone();
            tokio::spawn(async move {
                store
                    .take_session_enrollment_if_owner::<Value>(
                        &key,
                        user_id,
                        session_id,
                        0,
                        FactorMethod::Passkey,
                        &enrollment_id,
                    )
                    .await
                    .expect("concurrent Passkey consume")
                    .is_some()
            })
        })
        .collect::<Vec<_>>();
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.expect("consume task"));
    }
    assert_eq!(winners, 1);
    let stale_id = Uuid::new_v4().into_bytes().to_vec();
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 1 WHERE id = $1")
        .bind(user_id)
        .execute(&app.database)
        .await
        .expect("advance Passkey epoch");
    assert_eq!(
        repository::insert_authenticated_passkey(
            &app.database,
            user_id,
            0,
            &stale_id,
            &test_passkey(&stale_id),
        )
        .await
        .expect("stale Passkey persistence"),
        repository::AuthenticatedPasskeyPersistenceResult::AuthenticationChanged
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkey_finish_epoch_change_after_consumption_rejects_without_restore() {
    let app = TestApp::new("factor_security_passkey_epoch_race").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    let start = http::json_body(start).await;
    let enrollment_id = start["enrollment_id"]
        .as_str()
        .expect("enrollment id")
        .to_owned();
    let challenge = start["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("registration challenge")
        .to_owned();
    let pending_key = format!("chenxing:auth:session-enrollment:{user_id}:passkey");

    let mut lock = app
        .database
        .begin()
        .await
        .expect("Passkey epoch transaction");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut *lock)
        .await
        .expect("Passkey epoch lock");
    let router = app.router.clone();
    let cookie_for_task = cookie.clone();
    let csrf_for_task = csrf_token.clone();
    let enrollment_for_task = enrollment_id.clone();
    let finish = tokio::spawn(async move {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/security/passkeys/registration/finish")
                    .header("content-type", "application/json")
                    .header("cookie", cookie_for_task)
                    .header("x-csrf-token", csrf_for_task)
                    .body(Body::from(
                        serde_json::json!({
                            "enrollment_id": enrollment_for_task,
                            "credential": registration_fixture(&challenge, ISSUER)
                        })
                        .to_string(),
                    ))
                    .expect("Passkey finish request"),
            )
            .await
            .expect("Passkey finish response")
    });
    for _ in 0..10_000 {
        let pending: Option<String> = redis_connection(&app)
            .await
            .get(&pending_key)
            .await
            .expect("Passkey pending race read");
        if pending.is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let pending: Option<String> = redis_connection(&app)
        .await
        .get(&pending_key)
        .await
        .expect("Passkey pending after consume");
    assert!(
        pending.is_none(),
        "Passkey finish must consume before persistence"
    );
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1")
        .bind(user_id)
        .execute(&mut *lock)
        .await
        .expect("advance Passkey epoch");
    lock.commit().await.expect("commit Passkey epoch");
    assert_eq!(
        finish.await.expect("finish task").status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        repository::count_passkeys(&app.database, user_id)
            .await
            .expect("Passkey count"),
        0
    );
}
