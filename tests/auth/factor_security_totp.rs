use axum::http::{HeaderMap, Method, StatusCode, header::SET_COOKIE};
use chenxing_auth::{
    auth_factors::session::issue_primary_factor_session, users::domain::LoginInput,
};
use redis::AsyncCommands;
use serde_json::Value;
use totp_rs::TOTP;

use crate::{http, totp_time};

use super::factor_security_api::{
    PASSWORD, TestApp, confirm_totp, confirm_totp_on_router, csrf, redis_connection, start_totp,
};

#[tokio::test]
async fn no_factor_login_issues_session_and_pending_does_not_change_policy() {
    let app = TestApp::new("factor_security_login").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = http::set_cookies(&login);
    assert!(cookie.contains("chenxing_session="));
    let csrf_token = csrf(&cookie);
    let _: Value = http::json_body(login).await;

    let session_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("session count");
    assert_eq!(session_count, 1);

    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let issuer = url::Url::parse(setup["otpauth_url"].as_str().expect("otpauth URL"))
        .expect("parsed otpauth URL")
        .query_pairs()
        .find_map(|(key, value)| (key == "issuer").then(|| value.into_owned()));
    assert_eq!(issuer.as_deref(), Some("127.0.0.1"));

    let second_login = app.login(&username, PASSWORD).await;
    assert_eq!(second_login.status(), StatusCode::OK);

    let summary = app
        .request(
            Method::GET,
            "/api/v1/auth/security/factors",
            serde_json::json!({}),
            Some(("cookie", cookie.clone())),
            None,
        )
        .await;
    assert_eq!(summary.status(), StatusCode::OK);
    let summary = http::json_body(summary).await;
    assert_eq!(summary["totp_enabled"], false);
    assert_eq!(summary["available_methods"], serde_json::json!([]));
}
/// The password decision is deliberately made before the enrollment transaction.  Once the
/// enrollment commits, the Session write must take the account lock and convert the stale
/// password-only decision into a real factor-required ticket instead of issuing a Session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_enrollment_wins_before_password_session_write() {
    let app = TestApp::new("factor_security_login_race").await;
    let (user_id, username, _) = app.create_user().await;
    let authenticated = app
        .state
        .users
        .authenticate(
            LoginInput {
                identifier: username,
                password: PASSWORD.to_owned(),
                totp_code: None,
            },
            None,
        )
        .await
        .expect("authenticate password");
    assert!(
        app.state
            .factors
            .available_methods(user_id)
            .await
            .expect("factor inventory")
            .is_empty()
    );

    let mut enrollment = app.database.begin().await.expect("enrollment transaction");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut *enrollment)
        .await
        .expect("enrollment lock");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind([1_u8, 2, 3, 4].as_slice())
    .execute(&mut *enrollment)
    .await
    .expect("enrollment insert");
    enrollment.commit().await.expect("enrollment commit");

    let response = issue_primary_factor_session(
        &app.state,
        authenticated,
        "password",
        &HeaderMap::new(),
        None,
        chenxing_auth::auth_factors::session::StaleCredentialCode::InvalidCredentials,
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = http::json_body(response).await;
    assert_eq!(body["status"], "factor_required");
    assert_eq!(body["methods"], serde_json::json!(["totp"]));
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&app.database)
        .await
        .expect("session count"),
        0,
        "a factor-required result must not leave a password-only Session"
    );
}

#[tokio::test]
async fn unreadable_totp_pending_is_consumed_only_by_owner_and_can_restart() {
    let app = TestApp::new("factor_security_unknown_key").await;
    let (_, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let user_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(&username)
            .fetch_one(&app.database)
            .await
            .expect("user id");
    let key = format!("chenxing:auth:session-enrollment:{user_id}:totp");
    let mut connection = redis_connection(&app).await;
    let pending_json: String = connection.get(&key).await.expect("pending enrollment");
    let mut pending: Value = serde_json::from_str(&pending_json).expect("pending enrollment JSON");
    let ciphertext = pending["payload"]["encrypted_secret"]
        .as_array_mut()
        .expect("encrypted secret");
    let kid_length = ciphertext[3].as_u64().expect("kid length") as usize;
    for byte in &mut ciphertext[4..4 + kid_length] {
        *byte = Value::from(u64::from(b'Z'));
    }
    let _: () = connection
        .set(&key, serde_json::to_string(&pending).expect("pending JSON"))
        .await
        .expect("corrupt pending key id");

    let second = app.login(&username, PASSWORD).await;
    let second_cookie = http::set_cookies(&second);
    let second_csrf = csrf(&second_cookie);
    let wrong_owner = confirm_totp(
        &app,
        &second_cookie,
        &second_csrf,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        "000000",
    )
    .await;
    assert_eq!(wrong_owner.status(), StatusCode::BAD_REQUEST);
    assert!(
        redis_connection(&app)
            .await
            .get::<_, Option<String>>(&key)
            .await
            .expect("pending remains")
            .is_some()
    );

    let unavailable = confirm_totp(
        &app,
        &cookie,
        &csrf_token,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        "000000",
    )
    .await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let restarted = start_totp(&app, &cookie, &csrf_token).await;
    assert!(restarted["enrollment_id"].as_str().is_some());
}
#[tokio::test]
async fn authenticated_totp_confirmation_enables_factor_without_reissuing_session() {
    let app = TestApp::new("factor_security_totp").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth URL")).expect("TOTP");
    let enrollment_id = setup["enrollment_id"].as_str().expect("enrollment id");

    let invalid = confirm_totp(&app, &cookie, &csrf_token, enrollment_id, "000000").await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let confirmed = confirm_totp(
        &app,
        &cookie,
        &csrf_token,
        enrollment_id,
        &totp.generate(totp_time::previous_timestep(app.now)),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert!(
        confirmed
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none()
    );

    let enabled: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(enabled);

    let factor_login = app.login(&username, PASSWORD).await;
    assert_eq!(factor_login.status(), StatusCode::ACCEPTED);
    let pending = http::json_body(factor_login).await;
    assert_eq!(pending["status"], "factor_required");
    assert_eq!(pending["methods"], serde_json::json!(["totp"]));

    let passkey_start = app
        .request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(passkey_start.status(), StatusCode::OK);
    let passkey_start = http::json_body(passkey_start).await;
    assert!(passkey_start["enrollment_id"].as_str().is_some());
    assert!(
        passkey_start["options"]["publicKey"]["challenge"]
            .as_str()
            .is_some()
    );
}
#[tokio::test]
async fn enrollment_requires_session_csrf_and_the_starting_session() {
    let app = TestApp::new("factor_security_binding").await;
    let (_, username, _) = app.create_user().await;
    let first = app.login(&username, PASSWORD).await;
    let first_cookie = http::set_cookies(&first);
    let first_csrf = csrf(&first_cookie);
    let second = app.login(&username, PASSWORD).await;
    let second_cookie = http::set_cookies(&second);
    let second_csrf = csrf(&second_cookie);

    let no_session = app
        .request(
            Method::GET,
            "/api/v1/auth/security/factors",
            serde_json::json!({}),
            None,
            None,
        )
        .await;
    assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
    let no_csrf = app
        .request(
            Method::POST,
            "/api/v1/auth/security/totp/enrollment/start",
            serde_json::json!({}),
            Some(("cookie", first_cookie.clone())),
            None,
        )
        .await;
    assert_eq!(no_csrf.status(), StatusCode::BAD_REQUEST);

    let setup = start_totp(&app, &first_cookie, &first_csrf).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth URL")).expect("TOTP");
    let wrong_session = confirm_totp(
        &app,
        &second_cookie,
        &second_csrf,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        &totp.generate(totp_time::previous_timestep(app.now)),
    )
    .await;
    assert_eq!(wrong_session.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(wrong_session).await["code"],
        "invalid_factor_enrollment"
    );

    let (first_start, second_start) = tokio::join!(
        app.request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&first_cookie, &first_csrf)),
        ),
        app.request(
            Method::POST,
            "/api/v1/auth/security/passkeys/registration/start",
            serde_json::json!({}),
            None,
            Some((&first_cookie, &first_csrf)),
        )
    );
    let statuses = [first_start.status(), second_start.status()];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::CONFLICT));
}
#[tokio::test]
async fn epoch_change_rejects_enrollment_finish() {
    let app = TestApp::new("factor_security_epoch").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth URL")).expect("TOTP");
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1")
        .bind(user_id)
        .execute(&app.database)
        .await
        .expect("advance epoch");
    let response = confirm_totp(
        &app,
        &cookie,
        &csrf_token,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        &totp.generate(totp_time::previous_timestep(app.now)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let enabled: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(!enabled);
}

/// The epoch can change after Redis consumption but before the account insert acquires its
/// advisory lock.  This exercises the real HTTP enrollment path and proves both one-time
/// replay consumption and pending non-restoration on that race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn epoch_change_after_totp_consumption_rejects_without_restore() {
    let app = TestApp::new("factor_security_epoch_race").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let enrollment_id = setup["enrollment_id"]
        .as_str()
        .expect("enrollment id")
        .to_owned();
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let pending_key = format!("chenxing:auth:session-enrollment:{user_id}:totp");
    let replay_key = chenxing_auth::auth_factors::store::LoginTicketStore::totp_replay_key(
        user_id,
        totp_time::previous_timestep(app.now) / 30,
    );

    let mut lock = app.database.begin().await.expect("epoch race transaction");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut *lock)
        .await
        .expect("epoch race lock");
    let pending_before: Option<String> = redis_connection(&app)
        .await
        .get(&pending_key)
        .await
        .expect("pending before race");
    assert!(pending_before.is_some());

    let router = app.router.clone();
    let cookie_for_task = cookie.clone();
    let csrf_for_task = csrf_token.clone();
    let enrollment_for_task = enrollment_id.clone();
    let code = totp.generate(totp_time::previous_timestep(app.now));
    let confirmation = tokio::spawn(async move {
        confirm_totp_on_router(
            &router,
            &cookie_for_task,
            &csrf_for_task,
            &enrollment_for_task,
            &code,
        )
        .await
    });

    // Polling Redis observes the atomic Lua consume without introducing a wall-clock sleep.
    for _ in 0..10_000 {
        let pending: Option<String> = redis_connection(&app)
            .await
            .get(&pending_key)
            .await
            .expect("pending race read");
        if pending.is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let pending: Option<String> = redis_connection(&app)
        .await
        .get(&pending_key)
        .await
        .expect("pending after consume");
    assert!(
        pending.is_none(),
        "confirmation must consume before persistence"
    );
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1")
        .bind(user_id)
        .execute(&mut *lock)
        .await
        .expect("advance epoch while holding account lock");
    lock.commit().await.expect("commit epoch race");

    let response = confirmation.await.expect("confirmation task");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&app.database)
        .await
        .expect("factor count"),
        0
    );
    let replay_exists: bool = redis_connection(&app)
        .await
        .exists(replay_key)
        .await
        .expect("replay claim");
    assert!(
        replay_exists,
        "a valid code remains consumed after epoch loss"
    );
}
