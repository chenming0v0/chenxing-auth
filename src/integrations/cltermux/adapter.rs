//! CLtermux adapter: provider contract to validated application snapshots.

use serde_json::Value;

use super::{
    client::CltermuxClient,
    contract::AccountSnapshotDto,
    types::{AccountStatus, CredentialBundle, IntegrationError, LinkedAccountSnapshot},
    validation::validate_snapshot,
};

#[derive(Debug, Clone)]
pub struct ValidatedAccount {
    pub uid: String,
    pub subject: String,
    pub account_status: AccountStatus,
    pub snapshot: LinkedAccountSnapshot,
    pub snapshot_json: Value,
}

#[derive(Clone)]
pub struct CltermuxIntegration {
    client: CltermuxClient,
}

impl CltermuxIntegration {
    pub fn new(config: &crate::config::CltermuxConfig) -> Result<Self, IntegrationError> {
        Ok(Self {
            client: CltermuxClient::new(config)?,
        })
    }

    pub async fn verify(
        &self,
        credentials: CredentialBundle,
    ) -> Result<ValidatedAccount, IntegrationError> {
        let dto = self.client.verify(credentials).await?;
        let account = validate_dto(dto)?;
        if account.account_status == AccountStatus::Disabled {
            return Err(IntegrationError::AccountDisabled);
        }
        if account.account_status == AccountStatus::Missing {
            return Err(IntegrationError::AccountNotFound);
        }
        Ok(account)
    }

    pub async fn lookup(&self, uid: &str) -> Result<ValidatedAccount, IntegrationError> {
        validate_uid(uid)?;
        validate_dto(self.client.lookup(uid).await?)
    }
}

fn validate_uid(uid: &str) -> Result<(), IntegrationError> {
    let Some(id) = uid.strip_prefix("cltermux:") else {
        return Err(IntegrationError::AccountNotFound);
    };
    if id.is_empty() || id.len() > 18 || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(IntegrationError::AccountNotFound);
    }
    Ok(())
}

fn validate_dto(dto: AccountSnapshotDto) -> Result<ValidatedAccount, IntegrationError> {
    let snapshot =
        validate_snapshot(&dto).map_err(|_| IntegrationError::ProviderInvalidResponse)?;
    let snapshot_json =
        serde_json::to_value(&dto).map_err(|_| IntegrationError::ProviderInvalidResponse)?;
    Ok(ValidatedAccount {
        uid: dto.uid,
        subject: dto.subject,
        account_status: snapshot.account_status,
        snapshot,
        snapshot_json,
    })
}
