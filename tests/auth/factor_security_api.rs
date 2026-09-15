use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use chenxing_auth::{
    api, auth_factors::store::LoginTicketStore, clock::SharedClock, state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, harness, http, oauth_flow, totp_time};

const ADMIN_TOKEN: &str = "factor-security-admin-token";
pub(super) const PASSWORD: &str = "correct horse battery";
pub(super) const ISSUER: &str = "http://127.0.0.1:3000";

pub(super) struct TestApp {
    pub(super) router: Router,
    pub(super) state: AppState,
    pub(super) database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    pub(super) redis_url: String,
    pub(super) now: time::OffsetDateTime,
}

impl TestApp {
    pub(super) async fn new(test_name: &str) -> Self {
        Self::new_with_webauthn(test_name, "127.0.0.1", ISSUER).await
    }

    pub(super) async fn new_with_webauthn(test_name: &str, rp_id: &str, origin: &str) -> Self {
        let rp_id = rp_id.to_owned();
        let origin = origin.to_owned();
        let (state, database, key_directory, _admin_token, binary_name) =
            harness::HarnessBuilder::new(test_name)
                .admin_token(ADMIN_TOKEN)
                .configure(move |config| {
                    config.webauthn_rp_id = rp_id;
                    config.webauthn_origin = origin;
                    config.webauthn_rp_id_explicit = true;
                    config.webauthn_origin_explicit = true;
                })
                .build_state()
                .await;
        let now = totp_time::centered_now();
        let state = state.with_clock(SharedClock::fixed(now));
        let router = api::router(state.clone());
        oauth_flow::ensure_owner_bootstrapped(
            &router,
            &database,
            &binary_name,
            &Uuid::new_v4().simple().to_string(),
        )
        .await;
        db_isolation::isolate_user_ids(&database, &binary_name).await;
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        Self {
            router,
            state,
            database,
            key_directory,
            redis_url,
            now,
        }
    }

    pub(super) async fn create_user(&self) -> (i64, String, String) {
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
        let user_id = http::json_body(response).await["id"]
            .as_i64()
            .expect("user id");
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

    pub(super) async fn login(&self, identifier: &str, password: &str) -> axum::response::Response {
        self.request(
            Method::POST,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": identifier, "password": password}),
            None,
            None,
        )
        .await
    }

    pub(super) async fn request(
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

pub(super) async fn redis_connection(app: &TestApp) -> redis::aio::MultiplexedConnection {
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

pub(super) fn csrf(cookie: &str) -> String {
    http::cookie_value(cookie, "chenxing_csrf")
}

pub(super) fn test_passkey(credential_id: &[u8]) -> webauthn_rs::prelude::Passkey {
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

pub(super) fn registration_fixture(challenge: &str, origin: &str) -> Value {
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

pub(super) async fn start_totp(app: &TestApp, cookie: &str, csrf_token: &str) -> Value {
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
        panic!(
            "TOTP start failed with {status}: {}",
            http::json_body(response).await
        );
    }
    http::json_body(response).await
}

pub(super) async fn confirm_totp(
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

pub(super) async fn confirm_totp_on_router(
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
