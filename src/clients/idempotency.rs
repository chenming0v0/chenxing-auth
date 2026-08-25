//! Durable Client-operation idempotency primitives.
//!
//! The raw idempotency key is never persisted. PostgreSQL stores its SHA-256
//! digest plus the request fingerprint and the key-ring `kid` used to derive a
//! deterministic Client Secret. A retry supplies the raw key again, so the
//! service can reconstruct the same one-time credential without storing
//! plaintext or reversible secret material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    clients::domain::{ClientAuthMethod, ValidatedClientRegistration},
    config::AuthEncryptionKeyRing,
};

const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 128;
const SECRET_DOMAIN: &[u8] = b"chenxing.client-secret.idempotency.v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientIdempotencyError {
    #[error("idempotency key is invalid")]
    InvalidKey,
    #[error("the idempotency result references an unavailable secret key")]
    UnknownKeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedClientCreateResult {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub auth_method: String,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedClientRotationResult {
    pub client_id: String,
    pub secret_version: i64,
}

#[derive(Clone)]
pub struct IdempotencyKey(String);

impl std::fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IdempotencyKey(<redacted>)")
    }
}

impl IdempotencyKey {
    pub fn parse(value: &str) -> Result<Self, ClientIdempotencyError> {
        if value.is_empty()
            || value.len() > MAX_IDEMPOTENCY_KEY_LENGTH
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(ClientIdempotencyError::InvalidKey);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub(crate) struct ClientIdempotencyContext {
    actor_scope: String,
    key: IdempotencyKey,
    operation: &'static str,
    request_hash: [u8; 32],
}

impl std::fmt::Debug for ClientIdempotencyContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientIdempotencyContext")
            .field("actor_scope", &self.actor_scope)
            .field("key", &self.key)
            .field("operation", &self.operation)
            .field("request_hash", &"<sha256>")
            .finish()
    }
}

impl ClientIdempotencyContext {
    pub(crate) fn for_create(
        actor_scope: String,
        key: IdempotencyKey,
        registration: &ValidatedClientRegistration,
        auth_method: ClientAuthMethod,
    ) -> Self {
        let mut fingerprint = Fingerprint::new(b"client.create.v1");
        fingerprint.string(&registration.client_name);
        fingerprint.strings(&registration.redirect_uris);
        fingerprint.strings(&registration.scopes);
        fingerprint.string(auth_method.as_str());
        fingerprint.string(registration.logo_uri.as_deref().unwrap_or(""));
        fingerprint.string(registration.client_uri.as_deref().unwrap_or(""));
        Self {
            actor_scope,
            key,
            operation: "client.create",
            request_hash: fingerprint.finish(),
        }
    }

    pub(crate) fn for_rotation(actor_scope: String, key: IdempotencyKey, client_id: &str) -> Self {
        let mut fingerprint = Fingerprint::new(b"client.rotate.v1");
        fingerprint.string(client_id);
        Self {
            actor_scope,
            key,
            operation: "client.rotate",
            request_hash: fingerprint.finish(),
        }
    }

    pub(crate) fn actor_scope(&self) -> &str {
        &self.actor_scope
    }

    pub(crate) fn key_digest(&self) -> [u8; 32] {
        self.key.digest()
    }

    pub(crate) const fn operation(&self) -> &'static str {
        self.operation
    }

    pub(crate) const fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }

    pub(crate) fn derive_secret(
        &self,
        keys: &AuthEncryptionKeyRing,
        kid: &str,
    ) -> Result<String, ClientIdempotencyError> {
        let key = keys.key(kid).ok_or(ClientIdempotencyError::UnknownKeyId)?;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .expect("HMAC accepts every AUTH_ENCRYPTION_KEYS entry");
        mac.update(SECRET_DOMAIN);
        update_mac_part(&mut mac, self.actor_scope.as_bytes());
        update_mac_part(&mut mac, self.operation.as_bytes());
        update_mac_part(&mut mac, &self.request_hash);
        update_mac_part(&mut mac, self.key.as_bytes());
        Ok(format!(
            "cxs_{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }
}

struct Fingerprint(Sha256);

impl Fingerprint {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        update_digest_part(&mut digest, domain);
        Self(digest)
    }

    fn string(&mut self, value: &str) {
        update_digest_part(&mut self.0, value.as_bytes());
    }

    fn strings(&mut self, values: &[String]) {
        self.0.update((values.len() as u64).to_be_bytes());
        for value in values {
            self.string(value);
        }
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn update_digest_part(digest: &mut impl Digest, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn update_mac_part(mac: &mut impl Mac, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthEncryptionKey;

    fn keys() -> AuthEncryptionKeyRing {
        AuthEncryptionKeyRing::from_entries(
            "active".to_owned(),
            vec![
                ("old".to_owned(), AuthEncryptionKey::new([1; 32])),
                ("active".to_owned(), AuthEncryptionKey::new([2; 32])),
            ],
        )
        .expect("valid key ring")
    }

    fn registration() -> ValidatedClientRegistration {
        ValidatedClientRegistration {
            client_name: "Example".to_owned(),
            redirect_uris: vec!["https://example.com/cb".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            logo_uri: None,
            client_uri: None,
        }
    }

    #[test]
    fn key_parser_rejects_empty_whitespace_non_ascii_and_oversized_values() {
        for invalid in ["", "contains space", "包含中文"] {
            assert!(matches!(
                IdempotencyKey::parse(invalid),
                Err(ClientIdempotencyError::InvalidKey)
            ));
        }
        assert!(matches!(
            IdempotencyKey::parse(&"x".repeat(MAX_IDEMPOTENCY_KEY_LENGTH + 1)),
            Err(ClientIdempotencyError::InvalidKey)
        ));
    }

    #[test]
    fn same_actor_key_and_request_reconstruct_the_same_secret() {
        let first = ClientIdempotencyContext::for_create(
            "user:42".to_owned(),
            IdempotencyKey::parse("request-123").expect("key"),
            &registration(),
            ClientAuthMethod::Basic,
        );
        let retry = ClientIdempotencyContext::for_create(
            "user:42".to_owned(),
            IdempotencyKey::parse("request-123").expect("key"),
            &registration(),
            ClientAuthMethod::Basic,
        );

        let first_secret = first.derive_secret(&keys(), "active").expect("secret");
        let retry_secret = retry.derive_secret(&keys(), "active").expect("secret");
        assert_eq!(first_secret, retry_secret);
        assert!(first_secret.starts_with("cxs_"));
        assert!(!format!("{first:?}").contains("request-123"));
    }

    #[test]
    fn actor_key_request_and_kid_are_all_bound_into_the_secret() {
        let base = ClientIdempotencyContext::for_create(
            "user:42".to_owned(),
            IdempotencyKey::parse("request-123").expect("key"),
            &registration(),
            ClientAuthMethod::Basic,
        );
        let other_actor = ClientIdempotencyContext::for_create(
            "user:43".to_owned(),
            IdempotencyKey::parse("request-123").expect("key"),
            &registration(),
            ClientAuthMethod::Basic,
        );
        let other_key = ClientIdempotencyContext::for_create(
            "user:42".to_owned(),
            IdempotencyKey::parse("request-456").expect("key"),
            &registration(),
            ClientAuthMethod::Basic,
        );
        let other_request = ClientIdempotencyContext::for_rotation(
            "user:42".to_owned(),
            IdempotencyKey::parse("request-123").expect("key"),
            "client-1",
        );

        let keys = keys();
        let expected = base.derive_secret(&keys, "active").expect("secret");
        assert_ne!(
            expected,
            other_actor.derive_secret(&keys, "active").expect("secret")
        );
        assert_ne!(
            expected,
            other_key.derive_secret(&keys, "active").expect("secret")
        );
        assert_ne!(
            expected,
            other_request
                .derive_secret(&keys, "active")
                .expect("secret")
        );
        assert_ne!(expected, base.derive_secret(&keys, "old").expect("secret"));
    }
}
