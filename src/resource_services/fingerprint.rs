//! 操作指纹：只持久化 HMAC，绝不持久化凭据或凭据的非密钥哈希。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::users::domain::UserId;

const DOMAIN: &[u8] = b"resource-service\0operation-fingerprint\0v1\0";
const KEY_DOMAIN: &[u8] = b"resource-service\0operation-fingerprint-key\0v1\0";

type HmacSha256 = Hmac<Sha256>;

/// `hmac_key` 必须是从门户 `client_secret` 派生的 purpose 分离密钥，
/// 不能是用户凭据本身。
pub fn keyed_fingerprint(hmac_key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(DOMAIN);
    mac.update(message);
    encode_hex(&mac.finalize().into_bytes())
}

/// 从门户 `client_secret` 派生 HMAC 密钥。purpose 与 HTTP Basic 材料分离，
/// 不能把用户凭据或裸 `client_secret` 直接当 HMAC key。
pub fn fingerprint_hmac_key(client_secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(client_secret)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(KEY_DOMAIN);
    let bytes = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    key
}

pub fn create_message(
    provider_id: Uuid,
    binding_id: Uuid,
    user_id: UserId,
    identifier: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    push_field(&mut message, b"create");
    push_field(&mut message, provider_id.as_bytes());
    push_field(&mut message, binding_id.as_bytes());
    push_field(&mut message, &user_id.to_be_bytes());
    push_field(&mut message, identifier);
    push_field(&mut message, secret);
    message
}

pub fn refresh_message(
    provider_id: Uuid,
    binding_id: Uuid,
    user_id: UserId,
    refresh_token: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    push_field(&mut message, b"refresh");
    push_field(&mut message, provider_id.as_bytes());
    push_field(&mut message, binding_id.as_bytes());
    push_field(&mut message, &user_id.to_be_bytes());
    push_field(&mut message, refresh_token);
    message
}

pub fn revoke_message(provider_id: Uuid, binding_id: Uuid, user_id: UserId) -> Vec<u8> {
    let mut message = Vec::new();
    push_field(&mut message, b"revoke");
    push_field(&mut message, provider_id.as_bytes());
    push_field(&mut message, binding_id.as_bytes());
    push_field(&mut message, &user_id.to_be_bytes());
    message
}

fn push_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u32).to_be_bytes());
    message.extend_from_slice(field);
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn fingerprints_are_keyed_and_purpose_separated() {
        let client_secret = b"portal-client-secret-material";
        let key = fingerprint_hmac_key(client_secret);
        let provider = Uuid::from_u128(1);
        let binding = Uuid::from_u128(2);
        let create = keyed_fingerprint(
            &key,
            &create_message(provider, binding, 9, b"id", b"secret"),
        );
        assert_eq!(create.len(), 64);
        assert_eq!(
            create,
            keyed_fingerprint(
                &key,
                &create_message(provider, binding, 9, b"id", b"secret")
            )
        );
        assert_ne!(
            create,
            keyed_fingerprint(
                &fingerprint_hmac_key(b"other-client-secret"),
                &create_message(provider, binding, 9, b"id", b"secret")
            )
        );
        assert_ne!(
            create,
            keyed_fingerprint(
                client_secret,
                &create_message(provider, binding, 9, b"id", b"secret")
            )
        );
        assert_ne!(
            create,
            keyed_fingerprint(&key, &create_message(provider, binding, 9, b"id", b"other"))
        );
        assert_ne!(
            create,
            keyed_fingerprint(
                &key,
                &create_message(provider, binding, 9, b"other", b"secret")
            )
        );
        assert_ne!(
            create,
            keyed_fingerprint(
                &key,
                &create_message(provider, Uuid::nil(), 9, b"id", b"secret")
            )
        );
        assert_ne!(
            create,
            keyed_fingerprint(&key, &refresh_message(provider, binding, 9, b"token"))
        );
        assert_ne!(
            keyed_fingerprint(&key, &refresh_message(provider, binding, 9, b"token-a")),
            keyed_fingerprint(&key, &refresh_message(provider, binding, 9, b"token-b"))
        );
        assert!(!create.contains("secret"));
        assert_ne!(key, fingerprint_hmac_key(b"other-client-secret"));
        assert_eq!(key, fingerprint_hmac_key(client_secret));
    }
}
