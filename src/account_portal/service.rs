//! 消费方业务状态机入口。HTTP 调用提供方期间不持有数据库锁。

use std::sync::Arc;

use crate::clock::SharedClock;
use crate::oauth::providers::secrets::SecretManager;
use crate::sqlx::PgPool;

use super::SecretContext;
use super::client::AccountProviderClient;
use super::crypto::{decrypt_secret, encrypt_secret};
use super::secret::SecretString;
use super::service_error::ServiceError;
use super::store::Store;
use super::transport::{ProviderTransport, ReqwestProviderTransport};
use super::types::ProviderRow;

mod account;
mod admin;
mod bind;
mod refresh;
mod revoke;
mod worker;

pub use admin::ProviderWrite;

#[derive(Clone)]
pub struct AccountPortalService {
    store: Store,
    secrets: SecretManager,
    clock: SharedClock,
    transport: Arc<dyn ProviderTransport>,
    pool: PgPool,
}

impl AccountPortalService {
    pub fn new(
        pool: PgPool,
        secrets: SecretManager,
        clock: SharedClock,
    ) -> Result<Self, ServiceError> {
        let transport = ReqwestProviderTransport::production()
            .map_err(|_| ServiceError::ProviderUnavailable { retry_after: None })?;
        Ok(Self::with_transport(
            pool,
            secrets,
            clock,
            Arc::new(transport),
        ))
    }

    pub fn with_transport(
        pool: PgPool,
        secrets: SecretManager,
        clock: SharedClock,
        transport: Arc<dyn ProviderTransport>,
    ) -> Self {
        Self {
            store: Store::new(pool.clone()),
            secrets,
            clock,
            transport,
            pool,
        }
    }

    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    fn encrypt_provider_secret(
        &self,
        provider_id: uuid::Uuid,
        secret: &SecretString,
    ) -> Result<String, ServiceError> {
        Ok(encrypt_secret(
            &self.secrets,
            SecretContext::AccountPortalProvider(provider_id),
            secret,
        )?
        .encode())
    }

    fn decrypt_provider_secret(&self, row: &ProviderRow) -> Result<SecretString, ServiceError> {
        let ciphertext = super::crypto::EncryptedSecret::decode(&row.client_secret_ciphertext)?;
        Ok(decrypt_secret(
            &self.secrets,
            SecretContext::AccountPortalProvider(row.id),
            &ciphertext,
        )?)
    }

    fn encrypt_bundle(
        &self,
        provider_id: uuid::Uuid,
        binding_id: uuid::Uuid,
        plaintext: &SecretString,
    ) -> Result<String, ServiceError> {
        Ok(encrypt_secret(
            &self.secrets,
            SecretContext::AccountPortalBindingToken {
                provider: provider_id,
                binding: binding_id,
            },
            plaintext,
        )?
        .encode())
    }

    fn decrypt_bundle(
        &self,
        provider_id: uuid::Uuid,
        binding_id: uuid::Uuid,
        ciphertext: &str,
    ) -> Result<SecretString, ServiceError> {
        let encoded = super::crypto::EncryptedSecret::decode(ciphertext)?;
        Ok(decrypt_secret(
            &self.secrets,
            SecretContext::AccountPortalBindingToken {
                provider: provider_id,
                binding: binding_id,
            },
            &encoded,
        )?)
    }

    fn provider_client(
        &self,
        row: &ProviderRow,
    ) -> Result<AccountProviderClient<dyn ProviderTransport>, ServiceError> {
        let issuer = super::scalar::Issuer::parse(&row.issuer)
            .map_err(|_| ServiceError::InvalidInput("issuer"))?;
        let secret = self.decrypt_provider_secret(row)?;
        AccountProviderClient::new(
            self.transport.clone(),
            issuer,
            row.client_id.clone(),
            secret,
        )
        .map_err(ServiceError::Protocol)
    }

    async fn fail_operation(
        &self,
        provider_id: uuid::Uuid,
        operation_type: &str,
        idempotency_key: uuid::Uuid,
    ) -> Result<(), ServiceError> {
        let mut tx = self.pool.begin().await?;
        Store::mark_operation_failed(&mut tx, provider_id, operation_type, idempotency_key).await?;
        tx.commit().await?;
        Ok(())
    }
}
