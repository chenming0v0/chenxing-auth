//! 独立加密上下文、密钥目录隔离与 fail-closed 行为测试。

use std::path::PathBuf;

use uuid::Uuid;

use super::crypto::{
    ACCOUNT_PROVIDER_KEY_SUBDIRECTORY, CryptoError, EncryptedSecret, decrypt_secret,
    encrypt_secret, load_account_provider_secret_manager,
};
use super::secret::SecretString;
use crate::oauth::providers::secrets::{SecretContext, SecretError, SecretManager};

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "chenxing-portal-crypto-{}",
        Uuid::new_v4().simple()
    ))
}

#[test]
fn purpose_and_identity_are_bound_into_the_ciphertext() {
    let manager = SecretManager::from_key([7_u8; 32]);
    let provider = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let plaintext = SecretString::new("cxap_rt_storage-bundle");

    let ciphertext = encrypt_secret(
        &manager,
        SecretContext::ResourceServiceBindingToken { provider, binding },
        &plaintext,
    )
    .expect("encrypt");
    let decrypted = decrypt_secret(
        &manager,
        SecretContext::ResourceServiceBindingToken { provider, binding },
        &ciphertext,
    )
    .expect("decrypt");
    assert_eq!(decrypted.expose(), plaintext.expose());

    // 跨 purpose（同 provider + binding）必须失败。
    for context in [
        SecretContext::ResourceServiceOperation { provider, binding },
        SecretContext::ResourceServiceRevocation { provider, binding },
        SecretContext::ResourceServiceProvider(provider),
    ] {
        assert!(
            decrypt_secret(&manager, context, &ciphertext).is_err(),
            "context {context:?} must not decrypt another purpose"
        );
    }

    // 跨 provider / 跨 binding 必须失败。
    assert!(
        decrypt_secret(
            &manager,
            SecretContext::ResourceServiceBindingToken {
                provider: Uuid::new_v4(),
                binding,
            },
            &ciphertext,
        )
        .is_err()
    );
    assert!(
        decrypt_secret(
            &manager,
            SecretContext::ResourceServiceBindingToken {
                provider,
                binding: Uuid::new_v4(),
            },
            &ciphertext,
        )
        .is_err()
    );
}

#[test]
fn old_context_aad_bytes_are_unchanged() {
    let manager = SecretManager::from_key([9_u8; 32]);
    let legacy = manager
        .encrypt_for(SecretContext::Provider(7), "legacy-provider-secret")
        .expect("legacy encrypt");
    assert_eq!(
        manager
            .decrypt_for(SecretContext::Provider(7), &legacy)
            .expect("legacy decrypt"),
        "legacy-provider-secret"
    );
    assert!(
        manager
            .decrypt_for(SecretContext::Provider(8), &legacy)
            .is_err()
    );
    assert!(manager.decrypt_for(SecretContext::Smtp, &legacy).is_err());

    // 新 context 不得解密旧 provider 密文（或反之）。
    for context in [
        SecretContext::ResourceServiceProvider(Uuid::new_v4()),
        SecretContext::ResourceServiceBindingToken {
            provider: Uuid::new_v4(),
            binding: Uuid::new_v4(),
        },
    ] {
        assert!(manager.decrypt_for(context, &legacy).is_err());
    }
}

#[tokio::test]
async fn resource_service_key_lives_in_its_own_subdirectory_with_its_own_key() {
    let root = temp_root();
    let root_string = root.to_string_lossy().into_owned();
    let portal = load_account_provider_secret_manager(&root_string, false)
        .await
        .expect("portal manager");
    let portal_path = portal.path().expect("portal key path").to_path_buf();
    assert!(portal_path.ends_with(format!(
        "{ACCOUNT_PROVIDER_KEY_SUBDIRECTORY}/oauth-provider-secret.key"
    )));

    let root_for_old = root.clone();
    let legacy =
        tokio::task::spawn_blocking(move || SecretManager::load_or_generate(root_for_old, false))
            .await
            .expect("join")
            .expect("legacy manager");
    let legacy_path = legacy.path().expect("legacy key path").to_path_buf();
    assert_ne!(portal_path, legacy_path);
    assert!(legacy_path.ends_with("oauth-provider-secret.key"));

    let context = SecretContext::ResourceServiceProvider(Uuid::new_v4());
    let ciphertext =
        encrypt_secret(&portal, context, &SecretString::new("portal-secret")).expect("encrypt");
    assert!(
        decrypt_secret(&legacy, context, &ciphertext).is_err(),
        "different key files must not decrypt each other"
    );
    assert!(decrypt_secret(&portal, context, &ciphertext).is_ok());

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn missing_portal_key_with_persisted_ciphertext_fails_closed() {
    let root = temp_root();
    let root_string = root.to_string_lossy().into_owned();
    let manager = load_account_provider_secret_manager(&root_string, false)
        .await
        .expect("portal manager");
    let context = SecretContext::ResourceServiceProvider(Uuid::new_v4());
    let ciphertext =
        encrypt_secret(&manager, context, &SecretString::new("persisted")).expect("encrypt");
    let key_path = manager.path().expect("key path").to_path_buf();
    drop(manager);
    std::fs::remove_file(&key_path).expect("remove key");

    let result = load_account_provider_secret_manager(&root_string, true).await;
    match result {
        Ok(_) => panic!("must refuse to regenerate a key while ciphertext exists"),
        Err(CryptoError::Secret(SecretError::MissingKeyForPersistedSecrets)) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
    }
    assert!(!key_path.exists());
    assert!(!ciphertext.as_bytes().is_empty());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn encrypted_secret_debug_does_not_expose_bytes() {
    let ciphertext = EncryptedSecret::from_bytes(vec![1, 2, 3, 4]);
    let rendered = format!("{ciphertext:?}");
    assert!(!rendered.contains("[1, 2, 3, 4]"));
    assert!(rendered.contains("encrypted secret"));
}
