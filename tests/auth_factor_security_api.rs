use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, header::SET_COOKIE},
};
use base64::Engine;
use chenxing_auth::{
    api,
    auth_factors::{
        domain::FactorMethod, repository, session::issue_user_session, store::LoginTicketStore,
    },
    clock::SharedClock,
    config::Config,
    state::AppState,
    users::domain::LoginInput,
};
use redis::AsyncCommands;
use serde_json::Value;
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;
#[path = "support/totp_time.rs"]
mod totp_time;

const ADMIN_TOKEN: &str = "factor-security-admin-token";
const PASSWORD: &str = "correct horse battery";
const ISSUER: &str = "http://127.0.0.1:3000";

struct TestApp {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    redis_url: String,
    now: time::OffsetDateTime,
}

impl TestApp {
    async fn new(test_name: &str) -> Self {
        Self::new_with_webauthn(test_name, "127.0.0.1", ISSUER).await
    }

    async fn new_with_webauthn(test_name: &str, rp_id: &str, origin: &str) -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let database = db_isolation::isolated_pool(test_name, &database_url).await;
        let key_directory =
            std::env::temp_dir().join(format!("chenxing-factor-security-{}", Uuid::new_v4()));
        let mut config = Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            ISSUER.to_owned(),
            database_url,
            redis_url.clone(),
            3600,
        )
        .expect("test config");
        config.admin_token = ADMIN_TOKEN.to_owned();
        config.cookie_secure = false;
        config.key_directory = key_directory.to_string_lossy().into_owned();
        config.webauthn_rp_id = rp_id.to_owned();
        config.webauthn_origin = origin.to_owned();
        config.webauthn_rp_id_explicit = true;
        config.webauthn_origin_explicit = true;
        let now = totp_time::centered_now();
        let state = AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state")
            .with_clock(SharedClock::fixed(now));
        let router = api::router(state.clone());
        oauth_flow::ensure_owner_bootstrapped(
            &router,
            &database,
            test_name,
            &Uuid::new_v4().simple().to_string(),
        )
        .await;
        db_isolation::isolate_user_ids(&database, test_name).await;
        Self {
            router,
            state,
            database,
            key_directory,
            redis_url,
            now,
        }
    }

    async fn create_user(&self) -> (i64, String, String) {
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("factor-{suffix}");
        let email = format!("{username}@example.com");
        let response = self
            .request(
                Method::POST,
                "/api/v1/admin/users",
                serde_json::json!({
                    "username": username,
                    "email": email,
                    "password": PASSWORD,
                }),
                Some(("authorization", format!("Bearer {ADMIN_TOKEN}"))),
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let user_id = json(response).await["id"].as_i64().expect("user id");
        let store = LoginTicketStore::new(
            redis::Client::open(self.redis_url.as_str()).expect("factor Redis"),
        );
        for method in ["totp", "passkey"] {
            store
                .delete(&format!(
                    "chenxing:auth:session-enrollment:{user_id}:{method}"
                ))
                .await
                .expect("clear prior pending enrollment");
        }
        store
            .clear_totp_replay(user_id)
            .await
            .expect("clear prior TOTP replay claims");
        (user_id, username, email)
    }

    async fn login(&self, identifier: &str, password: &str) -> axum::response::Response {
        self.request(
            Method::POST,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": identifier, "password": password}),
            None,
            None,
        )
        .await
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        body: Value,
        extra_header: Option<(&str, String)>,
        auth: Option<(&str, &str)>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some((name, value)) = extra_header {
            builder = builder.header(name, value);
        }
        if let Some((cookie, csrf)) = auth {
            builder = builder
                .header("cookie", cookie)
                .header("x-csrf-token", csrf);
        }
        self.router
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("response")
    }
}

async fn redis_connection(app: &TestApp) -> redis::aio::MultiplexedConnection {
    redis::Client::open(app.redis_url.as_str())
        .expect("Redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection")
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.key_directory);
    }
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie")
                .split(';')
                .next()
                .expect("cookie pair")
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn csrf(cookie: &str) -> String {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned()
}

fn test_passkey(credential_id: &[u8]) -> webauthn_rs::prelude::Passkey {
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    let coordinate = encode(&[4; 32]);
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": encode(credential_id),
            "cred": {
                "type_": "ES256",
                "key": {"EC_EC2": {
                    "curve": "SECP256R1", "x": coordinate, "y": encode(&[5; 32])
                }}
            },
            "counter": 0,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }
    }))
    .expect("test Passkey")
}

fn registration_fixture(challenge: &str, origin: &str) -> Value {
    const CREDENTIAL_ID: &str =
        "4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw";
    const ATTESTATION_OBJECT: &str = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU-CNhi_5_oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ-aF5-lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp_wStyvOkTd4NlWHW8rQ";
    let client_data = serde_json::json!({
        "challenge": challenge,
        "clientExtensions": {},
        "hashAlgorithm": "SHA-256",
        "origin": origin,
        "type": "webauthn.create"
    });
    serde_json::json!({
        "id": CREDENTIAL_ID,
        "rawId": CREDENTIAL_ID,
        "response": {
            "attestationObject": ATTESTATION_OBJECT,
            "clientDataJSON": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&client_data).expect("client data JSON"))
        },
        "type": "public-key"
    })
}

async fn start_totp(app: &TestApp, cookie: &str, csrf_token: &str) -> Value {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/security/totp/enrollment/start")
                .header("content-type", "application/json")
                .header("host", "attacker-controlled.example")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_token)
                .body(Body::from("{}"))
                .expect("TOTP start request"),
        )
        .await;
    let response = response.expect("TOTP start response");
    if response.status() != StatusCode::OK {
        let status = response.status();
        panic!("TOTP start failed with {status}: {}", json(response).await);
    }
    json(response).await
}

async fn confirm_totp(
    app: &TestApp,
    cookie: &str,
    csrf_token: &str,
    enrollment_id: &str,
    code: &str,
) -> axum::response::Response {
    app.request(
        Method::POST,
        "/api/v1/auth/security/totp/enrollment/confirm",
        serde_json::json!({"enrollment_id": enrollment_id, "code": code}),
        None,
        Some((cookie, csrf_token)),
    )
    .await
}

async fn confirm_totp_on_router(
    router: &Router,
    cookie: &str,
    csrf_token: &str,
    enrollment_id: &str,
    code: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/security/totp/enrollment/confirm")
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_token)
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": enrollment_id,
                        "code": code,
                    })
                    .to_string(),
                ))
                .expect("TOTP confirmation request"),
        )
        .await
        .expect("TOTP confirmation response")
}

#[tokio::test]
async fn no_factor_login_issues_session_and_pending_does_not_change_policy() {
    let app = TestApp::new("factor_security_login").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = cookies(&login);
    assert!(cookie.contains("chenxing_session="));
    let csrf_token = csrf(&cookie);
    let _: Value = json(login).await;

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
    let summary = json(summary).await;
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

    let response = issue_user_session(
        &app.state,
        authenticated,
        "password",
        &HeaderMap::new(),
        None,
        chenxing_auth::auth_factors::session::StaleCredentialCode::InvalidCredentials,
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_passkey_finish_persists_and_consumes_once() {
    let app = TestApp::new("factor_security_passkey_finish").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = cookies(&login);
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
    let start_body = json(start).await;
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
    let second_cookie = cookies(&second_login);
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
    let other_cookie = cookies(&other_login);
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
    let other_start = json(other_start).await;
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
    assert_eq!(factor_login.status(), StatusCode::ACCEPTED);
    let factor_body = json(factor_login).await;
    assert_eq!(factor_body["status"], "factor_required");
    assert_eq!(factor_body["methods"], serde_json::json!(["passkey"]));
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
    let cookie = cookies(&login);
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
    let start = json(start).await;
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
    let cookie = cookies(&login);
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
    let start_body = json(start).await;
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
    let cookie = cookies(&login);
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
    let start = json(start).await;
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

#[tokio::test]
async fn unreadable_totp_pending_is_consumed_only_by_owner_and_can_restart() {
    let app = TestApp::new("factor_security_unknown_key").await;
    let (_, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = cookies(&login);
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
    let second_cookie = cookies(&second);
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
    let cookie = cookies(&login);
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
    let pending = json(factor_login).await;
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
    let passkey_start = json(passkey_start).await;
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
    let first_cookie = cookies(&first);
    let first_csrf = csrf(&first_cookie);
    let second = app.login(&username, PASSWORD).await;
    let second_cookie = cookies(&second);
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
        json(wrong_session).await["code"],
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
    let cookie = cookies(&login);
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
    let cookie = cookies(&login);
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

#[tokio::test]
async fn factor_removal_requires_password_and_revokes_current_session() {
    let app = TestApp::new("factor_security_remove").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth URL")).expect("TOTP");
    let confirmed = confirm_totp(
        &app,
        &cookie,
        &csrf_token,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        &totp.generate(totp_time::previous_timestep(app.now)),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);

    let wrong = app
        .request(
            Method::DELETE,
            "/api/v1/auth/security/factors/totp",
            serde_json::json!({"password": "wrong password"}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let still_enabled: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(still_enabled);

    let removed = app
        .request(
            Method::DELETE,
            "/api/v1/auth/security/factors/totp",
            serde_json::json!({"password": PASSWORD}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(removed.status(), StatusCode::OK);
    let clear_cookie = removed
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(clear_cookie.contains("Max-Age=0"));

    let session_after = app
        .request(
            Method::GET,
            "/api/v1/auth/security/factors",
            serde_json::json!({}),
            Some(("cookie", cookie.clone())),
            None,
        )
        .await;
    assert_eq!(session_after.status(), StatusCode::UNAUTHORIZED);
    let factor_exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(!factor_exists);
    let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1 AND action = 'user_totp_factor_remove'",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("removal audit");
    assert_eq!(audit_count, 1);
}
