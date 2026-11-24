use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use axum::{http::StatusCode, response::Response};
use base64::Engine;
use chenxing_auth::{
    auth_factors::{domain::FactorMethod, repository},
    sessions::cookies,
    users::domain::AuthenticatedUser,
};
use redis::AsyncCommands;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

use crate::{harness, http};

pub(super) const ORIGIN: &str = "http://127.0.0.1:3000";
pub(super) const RP_ID: &str = "127.0.0.1";
pub(super) const START: &str = "/api/v1/auth/passkeys/authentication/start";
pub(super) const FINISH: &str = "/api/v1/auth/passkeys/authentication/finish";

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

pub(super) struct TestAuthenticator {
    key: EcdsaKeyPair,
    credential_id: Vec<u8>,
    backup_eligible: bool,
}

impl TestAuthenticator {
    fn new(backup_eligible: bool) -> Self {
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
                .expect("generate a signing authenticator"),
            credential_id: Uuid::new_v4().into_bytes().to_vec(),
            backup_eligible,
        }
    }

    pub(super) fn passkey(&self, counter: u32) -> Passkey {
        let point = self.key.public_key().as_ref();
        serde_json::from_value(serde_json::json!({
            "cred": {
                "cred_id": encode(&self.credential_id),
                "cred": {
                    "type_": "ES256",
                    "key": {"EC_EC2": {
                        "curve": "SECP256R1",
                        "x": encode(&point[1..33]),
                        "y": encode(&point[33..65])
                    }}
                },
                "counter": counter,
                "transports": null,
                "user_verified": true,
                "backup_eligible": self.backup_eligible,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {"data": "None", "metadata": "None"},
                "attestation_format": "none"
            }
        }))
        .expect("authenticator Passkey")
    }

    pub(super) fn assertion(&self, challenge: &str, user_id: i64, counter: u32) -> Value {
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false
        }))
        .expect("client data JSON");
        let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        // UP 与 UV 始终置位；同步 Passkey 同时声明 BE，计数可以始终为零。
        authenticator_data.push(0x05 | if self.backup_eligible { 0x08 } else { 0 });
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self
            .key
            .sign(&SystemRandom::new(), &signed)
            .expect("sign assertion");
        serde_json::json!({
            "id": encode(&self.credential_id),
            "rawId": encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": encode(&authenticator_data),
                "clientDataJSON": encode(&client_data),
                "signature": encode(signature.as_ref()),
                "userHandle": encode(Uuid::from_u128(user_id as u128).as_bytes())
            },
            "clientExtensionResults": {}
        })
    }

    pub(super) fn result(&self, counter: u32, needs_update: bool) -> AuthenticationResult {
        serde_json::from_value(serde_json::json!({
            "cred_id": encode(&self.credential_id),
            "needs_update": needs_update,
            "user_verified": true,
            "backup_state": false,
            "backup_eligible": self.backup_eligible,
            "counter": counter,
            "extensions": {}
        }))
        .expect("verified authentication result")
    }
}

pub(super) struct Fixture {
    pub(super) app: harness::Harness,
    pub(super) authenticator: TestAuthenticator,
    pub(super) user_id: i64,
    pub(super) row_id: i64,
}

impl Fixture {
    pub(super) async fn new(counter: u32, backup_eligible: bool) -> Self {
        let app = harness::HarnessBuilder::new("passkey_counter")
            .max_connections(4)
            .bootstrap_owner()
            .build()
            .await;
        let suffix = Uuid::new_v4().simple();
        let user_id = chenxing_auth::sqlx::query_scalar(
            "INSERT INTO users
                 (username, email, canonical_email, password_hash, status, created_at)
             VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW()) RETURNING id",
        )
        .bind(format!("passkey-counter-{suffix}"))
        .bind(format!("passkey-counter-{suffix}@example.com"))
        .fetch_one(&app.database)
        .await
        .expect("Passkey user");
        let authenticator = TestAuthenticator::new(backup_eligible);
        assert_eq!(
            repository::insert_passkey_if_empty(
                &app.database,
                user_id,
                0,
                &authenticator.credential_id,
                &authenticator.passkey(counter),
            )
            .await
            .expect("insert authenticator"),
            repository::PasskeyPersistenceResult::Stored
        );
        let row_id = repository::list_passkeys_with_versions(&app.database, user_id)
            .await
            .expect("Passkey rows")[0]
            .id;
        Self {
            app,
            authenticator,
            user_id,
            row_id,
        }
    }

    pub(super) async fn ticket(&self) -> (String, String, String) {
        let holder = cookies::new_login_ticket_holder();
        let holder_hash = cookies::login_ticket_holder_hash(&holder);
        let (ticket, _) = self
            .app
            .state
            .factors
            .create_login_ticket(
                AuthenticatedUser::new(self.user_id, 0),
                vec![FactorMethod::Passkey],
                &holder_hash,
            )
            .await
            .expect("Passkey login ticket");
        let cookie = format!(
            "{}={ticket}; {}={holder}",
            cookies::login_ticket_cookie_name(false),
            cookies::login_ticket_holder_cookie_name(false),
        );
        (ticket, holder_hash, cookie)
    }

    pub(super) async fn post(&self, path: &str, body: Value, cookie: &str) -> Response {
        http::post_json_with_headers(&self.app.router, path, &[("cookie", cookie)], body).await
    }

    pub(super) async fn challenge(&self, cookie: &str) -> String {
        let response = self.post(START, serde_json::json!({}), cookie).await;
        assert_eq!(response.status(), StatusCode::OK);
        http::json_body(response).await["publicKey"]["challenge"]
            .as_str()
            .expect("authentication challenge")
            .to_owned()
    }

    pub(super) async fn stored(&self) -> repository::StoredPasskey {
        repository::find_passkey_row(&self.app.database, self.user_id, self.row_id)
            .await
            .expect("reload Passkey")
            .expect("Passkey remains registered")
    }

    pub(super) async fn session_count(&self) -> i64 {
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(self.user_id)
            .fetch_one(&self.app.database)
            .await
            .expect("session count")
    }

    pub(super) async fn redis(&self) -> redis::aio::MultiplexedConnection {
        redis::Client::open(self.app.state.config.redis_url.as_str())
            .expect("Redis client")
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection")
    }

    pub(super) async fn pending(&self, legacy_key: &str) -> Option<String> {
        let key = self.app.state.config.redis_keyspace.key(legacy_key);
        self.redis()
            .await
            .get(key)
            .await
            .expect("pending Passkey challenge")
    }
}

pub(super) fn counter(passkey: &Passkey) -> u64 {
    serde_json::to_value(passkey).expect("Passkey JSON")["cred"]["counter"]
        .as_u64()
        .expect("Passkey counter")
}
