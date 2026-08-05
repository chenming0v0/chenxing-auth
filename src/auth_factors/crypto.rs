use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rand::{RngCore, rngs::OsRng};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::AuthEncryptionKeyRing;

const NONCE_LENGTH: usize = 12;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_MAGIC: [u8; 2] = *b"CX";
const ENVELOPE_PREFIX_LENGTH: usize = ENVELOPE_MAGIC.len() + 2;
const MAX_KID_LENGTH: usize = 64;

#[derive(Debug, Error)]
pub enum SecretCryptoError {
    #[error("authentication key is invalid")]
    InvalidKey,
    #[error("encrypted secret is malformed")]
    Malformed,
    #[error("encrypted secret authentication failed")]
    Authentication,
    #[error("encrypted secret key is unavailable")]
    UnknownKeyId,
}

// DecryptedTotpSecret 包含解密后的 TOTP 种子明文。
// plaintext 使用 Zeroizing 包装，确保在 drop 时通过 volatile 写入自动清零，
// 防止敏感数据残留在堆内存、core dump 或交换分区中。
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedTotpSecret {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub needs_reencryption: bool,
}

// 手动实现 Debug 以防止 TOTP 种子泄漏到日志中。
// 注意：Zeroizing 的 Debug 实现会转发到内部值，因此必须在外层拦截。
impl std::fmt::Debug for DecryptedTotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedTotpSecret")
            .field("plaintext", &"<redacted>")
            .field("needs_reencryption", &self.needs_reencryption)
            .finish()
    }
}

pub fn encrypt_totp_secret(key: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
    let encrypted = encrypt_totp_secret_with_kid("legacy", key, secret)?;
    Ok(encrypted[ENVELOPE_PREFIX_LENGTH + "legacy".len()..].to_vec())
}

pub fn encrypt_totp_secret_with_ring(
    keys: &AuthEncryptionKeyRing,
    secret: &[u8],
) -> Result<Vec<u8>, SecretCryptoError> {
    encrypt_totp_secret_with_kid(keys.active_kid(), keys.active_key().as_bytes(), secret)
}

fn encrypt_totp_secret_with_kid(
    kid: &str,
    key: &[u8; 32],
    secret: &[u8],
) -> Result<Vec<u8>, SecretCryptoError> {
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH || !kid.is_ascii() {
        return Err(SecretCryptoError::Malformed);
    }
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SecretCryptoError::InvalidKey)?;
    let less_safe = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    // 这个缓冲区在 seal 之前持有明文种子副本。用 Zeroizing 包装，
    // 保证即使提前返回错误，明文也会在 drop 时被清零。
    // 传入 &mut *buffer 而非 &mut buffer：seal_in_place_append_tag 要求
    // InOut: AsMut<[u8]> + Extend<&u8>，而 Zeroizing 未实现 Extend，
    // 需要通过 DerefMut 取到内层 Vec<u8>。
    let mut buffer = Zeroizing::new(secret.to_vec());
    less_safe
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut *buffer)
        .map_err(|_| SecretCryptoError::Authentication)?;
    let mut output =
        Vec::with_capacity(ENVELOPE_PREFIX_LENGTH + kid.len() + NONCE_LENGTH + buffer.len());
    output.extend_from_slice(&ENVELOPE_MAGIC);
    output.push(ENVELOPE_VERSION);
    output.push(kid.len() as u8);
    output.extend_from_slice(kid.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    // buffer 此时已是密文，output 只承载密文，无需清零语义。
    output.extend_from_slice(&buffer);
    Ok(output)
}

pub fn decrypt_totp_secret(
    key: &[u8; 32],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretCryptoError> {
    let nonce_offset = if encrypted.starts_with(&ENVELOPE_MAGIC) {
        let (_, nonce_offset) = envelope_metadata(encrypted)?;
        nonce_offset
    } else {
        0
    };
    decrypt_payload(key, encrypted, nonce_offset)
}

pub fn decrypt_totp_secret_with_ring(
    keys: &AuthEncryptionKeyRing,
    encrypted: &[u8],
) -> Result<DecryptedTotpSecret, SecretCryptoError> {
    let (stored_kid, nonce_offset) = if encrypted.starts_with(&ENVELOPE_MAGIC) {
        let (kid, nonce_offset) = envelope_metadata(encrypted)?;
        (Some(kid), nonce_offset)
    } else if is_legacy_ciphertext(encrypted) {
        (None, 0)
    } else {
        return Err(SecretCryptoError::Malformed);
    };

    let mut candidates = Vec::new();
    if let Some(kid) = stored_kid.as_deref() {
        let Some(key) = keys.key(kid) else {
            return Err(SecretCryptoError::UnknownKeyId);
        };
        candidates.push(key);
    } else {
        candidates.extend(keys.iter().map(|(_, key)| key));
    }

    for key in candidates {
        match decrypt_payload(key.as_bytes(), encrypted, nonce_offset) {
            Ok(plaintext) => {
                let needs_reencryption = stored_kid
                    .as_deref()
                    .map(|kid| kid != keys.active_kid())
                    .unwrap_or(true);
                return Ok(DecryptedTotpSecret {
                    plaintext,
                    needs_reencryption,
                });
            }
            Err(SecretCryptoError::Authentication) => continue,
            Err(error) => return Err(error),
        }
    }

    Err(SecretCryptoError::Authentication)
}

fn decrypt_payload(
    key: &[u8; 32],
    encrypted: &[u8],
    nonce_offset: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretCryptoError> {
    if encrypted.len() < nonce_offset + NONCE_LENGTH + aead::AES_256_GCM.tag_len() {
        return Err(SecretCryptoError::Malformed);
    }
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SecretCryptoError::InvalidKey)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; NONCE_LENGTH] = encrypted[nonce_offset..nonce_offset + NONCE_LENGTH]
        .try_into()
        .map_err(|_| SecretCryptoError::Malformed)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    // open_in_place 会就地解密，因此这个缓冲区解密后直接持有明文种子。
    // 先包进 Zeroizing，再原地截断复用同一块内存：
    // 旧实现额外做 plaintext.to_vec()，等于在堆上留下第二份不清零的明文。
    let mut payload = Zeroizing::new(encrypted[nonce_offset + NONCE_LENGTH..].to_vec());
    let plaintext_length = less_safe
        .open_in_place(nonce, Aad::empty(), payload.as_mut_slice())
        .map_err(|_| SecretCryptoError::Authentication)?
        .len();
    // 去掉尾部 GCM tag；truncate 不会释放容量，多余字节仍由 Zeroizing 清零。
    payload.truncate(plaintext_length);
    Ok(payload)
}

fn envelope_metadata(encrypted: &[u8]) -> Result<(String, usize), SecretCryptoError> {
    if encrypted.len() < ENVELOPE_PREFIX_LENGTH {
        return Err(SecretCryptoError::Malformed);
    }
    if !encrypted.starts_with(&ENVELOPE_MAGIC) || encrypted[2] != ENVELOPE_VERSION {
        return Err(SecretCryptoError::Malformed);
    }
    let kid_length = encrypted[3] as usize;
    if kid_length == 0 || kid_length > MAX_KID_LENGTH {
        return Err(SecretCryptoError::Malformed);
    }
    let kid_end = ENVELOPE_PREFIX_LENGTH + kid_length;
    if encrypted.len() < kid_end + NONCE_LENGTH + aead::AES_256_GCM.tag_len() {
        return Err(SecretCryptoError::Malformed);
    }
    let kid = std::str::from_utf8(&encrypted[ENVELOPE_PREFIX_LENGTH..kid_end])
        .map_err(|_| SecretCryptoError::Malformed)?
        .to_owned();
    Ok((kid, kid_end))
}

fn is_legacy_ciphertext(encrypted: &[u8]) -> bool {
    encrypted.len() >= NONCE_LENGTH + aead::AES_256_GCM.tag_len()
        && !encrypted.starts_with(&ENVELOPE_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthEncryptionKey;

    fn rotated_ring(active_kid: &str) -> AuthEncryptionKeyRing {
        AuthEncryptionKeyRing::from_entries(
            active_kid.to_owned(),
            vec![
                ("old".to_owned(), AuthEncryptionKey::new([1; 32])),
                ("new".to_owned(), AuthEncryptionKey::new([2; 32])),
            ],
        )
        .expect("valid key ring")
    }

    #[test]
    fn encrypted_secret_records_kid_and_survives_key_rotation() {
        let old_ring = rotated_ring("old");
        let encrypted =
            encrypt_totp_secret_with_ring(&old_ring, b"totp-secret").expect("encrypt secret");

        let rotated = rotated_ring("new");
        let decrypted =
            decrypt_totp_secret_with_ring(&rotated, &encrypted).expect("decrypt with previous key");
        assert_eq!(decrypted.plaintext.as_slice(), b"totp-secret");
        assert!(decrypted.needs_reencryption);
    }

    #[test]
    fn legacy_secret_is_read_and_marked_for_reencryption() {
        let legacy = encrypt_totp_secret(&[1; 32], b"legacy-secret").expect("encrypt secret");
        let rotated = rotated_ring("new");
        let decrypted = decrypt_totp_secret_with_ring(&rotated, &legacy).expect("decrypt secret");

        assert_eq!(decrypted.plaintext.as_slice(), b"legacy-secret");
        assert!(decrypted.needs_reencryption);
    }

    #[test]
    fn unknown_kid_is_not_retried_with_another_key() {
        let encrypted =
            encrypt_totp_secret_with_ring(&rotated_ring("old"), b"secret").expect("encrypt secret");
        let keys = AuthEncryptionKeyRing::single(AuthEncryptionKey::new([2; 32]));

        assert!(matches!(
            decrypt_totp_secret_with_ring(&keys, &encrypted),
            Err(SecretCryptoError::UnknownKeyId)
        ));
    }

    // 内存清零本身无法在安全 Rust 中断言：drop 后读取已释放内存是 UB。
    // 这里只能验证 Zeroizing 包装没有破坏功能语义，以及 Debug 不泄漏种子。
    #[test]
    fn decrypted_secret_debug_does_not_leak_seed_bytes() {
        let ring = rotated_ring("new");
        let seed = b"debug-leak-canary";
        let encrypted = encrypt_totp_secret_with_ring(&ring, seed).expect("encrypt secret");
        let decrypted = decrypt_totp_secret_with_ring(&ring, &encrypted).expect("decrypt secret");

        let rendered = format!("{decrypted:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("debug-leak-canary"));
        // Zeroizing 的 Debug 会转发到 Vec<u8>，即打印出裸字节序列；
        // 断言字节数组的 Debug 形式也不出现，确认外层 Debug 真的拦截住了。
        let raw_bytes = format!("{:?}", seed.as_slice());
        assert!(!rendered.contains(&raw_bytes));
    }

    #[test]
    fn zeroizing_plaintext_still_round_trips_through_reencryption() {
        let old_ring = rotated_ring("old");
        let seed = b"JBSWY3DPEHPK3PXP";
        let encrypted = encrypt_totp_secret_with_ring(&old_ring, seed).expect("encrypt secret");

        let rotated = rotated_ring("new");
        let decrypted =
            decrypt_totp_secret_with_ring(&rotated, &encrypted).expect("decrypt with previous key");
        assert!(decrypted.needs_reencryption);

        // 模拟 reencrypt_totp_secret_if_needed：Zeroizing 通过 Deref 直接参与重新加密。
        let replacement =
            encrypt_totp_secret_with_ring(&rotated, &decrypted.plaintext).expect("reencrypt");
        let reread = decrypt_totp_secret_with_ring(&rotated, &replacement).expect("decrypt again");

        assert_eq!(reread.plaintext.as_slice(), seed.as_slice());
        assert!(!reread.needs_reencryption);
    }

    #[test]
    fn cloned_decrypted_secret_preserves_plaintext() {
        let ring = rotated_ring("new");
        let encrypted = encrypt_totp_secret_with_ring(&ring, b"clone-me").expect("encrypt secret");
        let decrypted = decrypt_totp_secret_with_ring(&ring, &encrypted).expect("decrypt secret");

        // Zeroizing<Vec<u8>> 的 Clone 会产生同样具备清零语义的副本。
        let cloned = decrypted.clone();
        assert_eq!(cloned.plaintext.as_slice(), b"clone-me");
        assert_eq!(cloned, decrypted);
    }

    #[test]
    fn decrypt_drops_gcm_tag_from_plaintext_length() {
        let ring = rotated_ring("new");
        let seed = b"exact-length-seed";
        let encrypted = encrypt_totp_secret_with_ring(&ring, seed).expect("encrypt secret");
        let decrypted = decrypt_totp_secret_with_ring(&ring, &encrypted).expect("decrypt secret");

        // truncate 之后长度必须等于原始种子长度，不能带上 16 字节 tag。
        assert_eq!(decrypted.plaintext.len(), seed.len());
    }
}
