//! Account Provider v1 消费方加密边界。
//!
//! 复用 [`SecretManager`]，不复制旧密钥、不新增第二套信封格式。密钥固定位于
//! `KEY_DIRECTORY/account-provider-v1/oauth-provider-secret.key` 的独立子目录：
//! 与旧 provider/SMTP 主密钥、旧 `linked_accounts` 令牌都不同文件，互不覆盖。
//!
//! 用途隔离由 [`SecretContext`] 的类型化变体表达：
//!
//! - 提供方配置：`SecretContext::AccountPortalProvider(provider)`（仅 provider UUID）
//! - 绑定令牌包：`SecretContext::AccountPortalBindingToken { provider, binding }`
//! - 操作上下文：`SecretContext::AccountPortalOperation { provider, binding }`
//! - 撤销任务：`SecretContext::AccountPortalRevocation { provider, binding }`
//!
//! 旧变体（`Provider` / `Smtp` / `AccountProvider`）的 AAD 字节完全不变。
//!
//! 这里只提供**可逆密文包**，不提供任何 one-way hash 路径；原始用户凭据在本模块
//! 完全没有持久化 API。

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::oauth::providers::secrets::{SecretContext, SecretError, SecretManager};

use super::secret::SecretString;

/// 与旧主密钥隔离的子目录名。
pub const ACCOUNT_PROVIDER_KEY_SUBDIRECTORY: &str = "account-provider-v1";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("account provider secret key loading failed: {0}")]
    Secret(#[from] SecretError),
    #[error("account provider secret key blocking task failed")]
    BlockingTask,
}

/// 在阻塞线程池加载独立子目录里的主密钥。
///
/// `has_persisted_ciphertext` 必须由调用方在调用前用严格查询得到（下一块的 DB
/// 步骤）：缺钥且已有密文时 [`SecretManager::load_or_generate`] 会 fail closed，
/// 不会生成新钥把旧密文变成不可读。
pub async fn load_account_provider_secret_manager(
    key_directory: &str,
    has_persisted_ciphertext: bool,
) -> Result<SecretManager, CryptoError> {
    let directory = PathBuf::from(key_directory).join(ACCOUNT_PROVIDER_KEY_SUBDIRECTORY);
    tokio::task::spawn_blocking(move || {
        SecretManager::load_or_generate(directory, has_persisted_ciphertext)
    })
    .await
    .map_err(|_| CryptoError::BlockingTask)?
    .map_err(CryptoError::Secret)
}

/// 可逆密文包。不解密拿不到明文，且不实现明文 `Debug` / `Serialize`。
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecret(Vec<u8>);

impl EncryptedSecret {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 便于写入文本列；仍是密文，不是明文。
    pub fn encode(&self) -> String {
        SecretManager::encode(&self.0)
    }

    pub fn decode(value: &str) -> Result<Self, SecretError> {
        SecretManager::decode(value).map(Self)
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<encrypted secret {} bytes>", self.0.len())
    }
}

/// 加密明文（提供方 `client_secret` 或令牌包 JSON）。
pub fn encrypt_secret(
    manager: &SecretManager,
    context: SecretContext,
    plaintext: &SecretString,
) -> Result<EncryptedSecret, SecretError> {
    manager
        .encrypt_for(context, plaintext.expose())
        .map(EncryptedSecret)
}

/// 解密。上下文（provider / binding / purpose）不一致时 AEAD 校验必然失败。
pub fn decrypt_secret(
    manager: &SecretManager,
    context: SecretContext,
    ciphertext: &EncryptedSecret,
) -> Result<SecretString, SecretError> {
    manager
        .decrypt_for(context, ciphertext.as_bytes())
        .map(SecretString::new)
}
