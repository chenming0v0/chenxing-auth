//! Durable idempotency context for wallet purchase mutations.
//!
//! Raw keys never reach PostgreSQL. The database stores only a SHA-256 digest
//! of the key and a request fingerprint, while the committed JSON result is
//! retained for replay during the bounded idempotency window.

use sha2::{Digest, Sha256};

use crate::{clients::idempotency::IdempotencyKey, users::domain::UserId};

#[derive(Debug, Clone, Copy)]
pub struct WalletIdempotencyContext {
    user_id: UserId,
    operation: &'static str,
    key_digest: [u8; 32],
    request_hash: [u8; 32],
}

impl WalletIdempotencyContext {
    fn from_key(
        user_id: UserId,
        operation: &'static str,
        domain: &[u8],
        key: &IdempotencyKey,
        input_id: i64,
    ) -> Self {
        let mut fingerprint = Sha256::new();
        update_part(&mut fingerprint, domain);
        update_part(&mut fingerprint, &input_id.to_be_bytes());
        Self {
            user_id,
            operation,
            key_digest: key.digest(),
            request_hash: fingerprint.finalize().into(),
        }
    }

    pub(crate) fn user_id(&self) -> UserId {
        self.user_id
    }

    pub(crate) fn operation(&self) -> &'static str {
        self.operation
    }

    pub(crate) fn key_digest(&self) -> &[u8; 32] {
        &self.key_digest
    }

    pub(crate) fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }
}

impl WalletIdempotencyContext {
    pub fn plan(user_id: UserId, key: &IdempotencyKey, plan_id: i64) -> Self {
        Self::from_key(
            user_id,
            "wallet.plan_purchase",
            b"wallet.plan_purchase.v1",
            key,
            plan_id,
        )
    }

    pub fn addon(user_id: UserId, key: &IdempotencyKey, addon_id: i64) -> Self {
        Self::from_key(
            user_id,
            "wallet.quota_addon_purchase",
            b"wallet.quota_addon_purchase.v1",
            key,
            addon_id,
        )
    }
}

fn update_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_fingerprint_binds_operation_and_input() {
        let key = IdempotencyKey::parse("purchase-1").expect("key");
        let plan = WalletIdempotencyContext::plan(7, &key, 10);
        let same = WalletIdempotencyContext::plan(7, &key, 10);
        let other_plan = WalletIdempotencyContext::plan(7, &key, 11);
        let addon = WalletIdempotencyContext::addon(7, &key, 10);
        assert_eq!(plan.key_digest(), same.key_digest());
        assert_eq!(plan.request_hash(), same.request_hash());
        assert_ne!(plan.request_hash(), other_plan.request_hash());
        assert_ne!(plan.request_hash(), addon.request_hash());
        assert_eq!(plan.user_id(), 7);
    }
}
