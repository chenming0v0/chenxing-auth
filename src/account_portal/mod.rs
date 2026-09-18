//! 通用账号提供方 v1 消费方基础模块。
//!
//! 本模块包含**产品中立**的协议消费逻辑：元数据 / 快照 / 令牌包的严格类型与
//! 校验、固定五路径的安全 HTTP 客户端、独立可逆加密上下文，以及 0058 四张新表
//! 的 SQL 出口。它不引用旧的适配器与 `linked_accounts` 路径，也不实现提供方端点。
//!
//! 术语边界：本协议不是 OAuth / OIDC / SCIM，也不实现 password grant；它是由
//! 辰星门户在显式披露后发起的「受信任门户凭据委托」，新授权只读 `account:read`。
//! 提供方 issuer 是提供方自身的 HTTPS origin，**不是**辰星的 OIDC `APP_ISSUER`。

pub mod admin_handlers;
mod bundle;
mod client;
mod crypto;
mod error;
mod fingerprint;
mod metadata;
pub mod portal_handlers;
mod request;
mod response;
pub(crate) mod routes;
mod scalar;
mod secret;
mod service;
mod service_error;
mod snapshot;
pub(crate) mod store;
mod transport;
mod types;
mod views;

pub use bundle::{
    ACCESS_TOKEN_PREFIX, ACCOUNT_READ_SCOPE, AccessToken, MAX_EXPIRES_IN_SECONDS, PROTOCOL_NAME,
    REFRESH_TOKEN_PREFIX, RefreshBinding, RefreshToken, TOKEN_TYPE_BEARER, TokenBundle,
};
pub use client::{
    ACCOUNT_PATH, AccountProviderClient, LINK_SESSIONS_PATH, MAX_REQUEST_BYTES, METADATA_PATH,
    REFRESH_PATH, REVOKE_PATH,
};
pub use crypto::{
    ACCOUNT_PROVIDER_KEY_SUBDIRECTORY, CryptoError, EncryptedSecret, decrypt_secret,
    encrypt_secret, load_account_provider_secret_manager,
};
pub use error::{ClientError, KnownErrorCode, ProtocolError, ProviderFailure};
pub use fingerprint::{create_message, keyed_fingerprint, refresh_message, revoke_message};
pub use metadata::{ACCOUNT_READ_CAPABILITY, CredentialLabels, ProviderMetadata};
pub use request::{
    CreateLinkSessionRequest, Credentials, MAX_CREDENTIAL_BYTES, RefreshLinkSessionRequest,
    RevokeLinkSessionRequest,
};
pub use scalar::{Issuer, SafeNumber, UtcTime};
pub use secret::SecretString;
pub use service::AccountPortalService;
pub use service_error::ServiceError;
pub use snapshot::{
    AccountSnapshot, AccountStatus, FieldValue, MAX_SNAPSHOT_FIELDS, SNAPSHOT_SCHEMA_VERSION,
    SnapshotField, Subscription,
};
pub use store::{Store, StoreError, has_persisted_ciphertext};
pub use transport::{
    CONNECT_TIMEOUT, HttpMethod, MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, ProviderHttpRequest,
    ProviderHttpResponse, ProviderTransport, ReqwestProviderTransport, TOTAL_TIMEOUT,
    TransportError, TransportFuture, clamp_retry_after_seconds,
};
pub use types::{
    BindingRow, ExistingOperation, OPERATION_CREATE, OPERATION_REFRESH, OPERATION_REVOKE,
    OperationRow, OutboxRow, ProviderRow, classify_existing_operation,
};
pub use views::{AdminProviderView, BindingView, PublicProviderView};

// 加密上下文变体由 `crate::oauth::providers::secrets::SecretContext` 定义；
// 消费方通过 `load_account_provider_secret_manager` 取得独立的 `SecretManager`。
pub use crate::oauth::providers::secrets::SecretContext;

#[cfg(test)]
mod bundle_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod crypto_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod snapshot_tests;
