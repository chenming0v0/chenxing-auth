use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::*;
use crate::settings::account_providers::{
    ACCOUNT_PROVIDERS_KEY, AccountAdapter, AccountProviderError as Error, AccountProviderInput,
    AccountProviderSummary, RuntimeAccountProvider, StoredAccountProvider, decode,
    validate_metadata,
};

impl SettingsService {
    pub async fn account_providers(&self) -> Result<Vec<AccountProviderSummary>, Error> {
        Ok(self
            .stored_account_providers()
            .await?
            .iter()
            .map(|row| row.summary())
            .collect())
    }

    async fn stored_account_providers(&self) -> Result<Vec<StoredAccountProvider>, Error> {
        decode(
            repository::get_text(&self.pool, ACCOUNT_PROVIDERS_KEY)
                .await?
                .as_deref(),
        )
    }

    pub async fn account_provider(
        &self,
        slug: &str,
    ) -> Result<Option<RuntimeAccountProvider>, Error> {
        self.stored_account_providers()
            .await?
            .into_iter()
            .find(|row| row.slug == slug && row.enabled)
            .map(|row| self.runtime_account_provider(row))
            .transpose()
    }

    pub async fn account_provider_for_client(
        &self,
        client: &str,
    ) -> Result<Option<RuntimeAccountProvider>, Error> {
        self.stored_account_providers()
            .await?
            .into_iter()
            .find(|row| row.enabled && row.allowed_client_ids.iter().any(|id| id == client))
            .map(|row| self.runtime_account_provider(row))
            .transpose()
    }

    fn runtime_account_provider(
        &self,
        row: StoredAccountProvider,
    ) -> Result<RuntimeAccountProvider, Error> {
        let outbound_token = self.secrets.decrypt_for(
            SecretContext::AccountProvider(row.id),
            &SecretManager::decode(&row.outbound_ciphertext)?,
        )?;
        Ok(RuntimeAccountProvider {
            slug: row.slug,
            name: row.name,
            version: row.version,
            config: crate::config::CltermuxConfig {
                base_url: url::Url::parse(&row.base_url).map_err(|_| Error::Unavailable)?,
                outbound_token,
                inbound_token_digest: row.inbound_digest,
                allowed_client_ids: row.allowed_client_ids,
            },
        })
    }

    pub async fn save_account_provider(
        &self,
        input: AccountProviderInput,
        audit: &AuditService,
        credential: ManagementActorCredential,
        event: AuditEvent,
    ) -> Result<AccountProviderSummary, Error> {
        validate_metadata(
            &input.slug,
            &input.name,
            &input.base_url,
            &input.allowed_client_ids,
        )?;
        if input.expected_version < 0 {
            return Err(Error::Invalid("expected_version"));
        }
        for token in [&input.outbound_token, &input.inbound_token]
            .into_iter()
            .flatten()
        {
            crate::config::validate_interop_token(token, "account_provider_token")
                .map_err(|_| Error::Invalid("token"))?;
            if token.len() > 4096 {
                return Err(Error::Invalid("token"));
            }
        }
        let mut tx = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageIdentityProviders,
        )
        .await?;
        let mut rows = lock_registry(&mut tx).await?;
        let position = rows.iter().position(|row| row.slug == input.slug);
        let existing = position.map(|p| &rows[p]);
        if existing.map_or(0, |row| row.version) != input.expected_version {
            return Err(Error::Conflict);
        }
        if rows.iter().any(|row| {
            row.slug != input.slug
                && row
                    .allowed_client_ids
                    .iter()
                    .any(|id| input.allowed_client_ids.contains(id))
        }) {
            return Err(Error::ClientConflict);
        }
        if position.is_none() && rows.len() >= 100 {
            return Err(Error::Invalid("provider_limit"));
        }
        // A bound provider's endpoint is its identity authority. Do not silently
        // reassign old UID bindings to an unrelated database when editing its URL.
        let base_url = url::Url::parse(&input.base_url)
            .map_err(|_| Error::Invalid("base_url"))?
            .to_string();
        if existing.is_some_and(|row| row.base_url != base_url) {
            let bound: bool = crate::sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM linked_accounts WHERE provider_slug = $1)",
            )
            .bind(&input.slug)
            .fetch_one(&mut *tx)
            .await?;
            if bound {
                return Err(Error::Invalid("bound_provider_url"));
            }
        }
        let id = existing.map_or_else(Uuid::new_v4, |row| row.id);
        let outbound = match input.outbound_token {
            Some(token) => token,
            None => self.secrets.decrypt_for(
                SecretContext::AccountProvider(id),
                &SecretManager::decode(
                    &existing
                        .ok_or(Error::Invalid("outbound_token"))?
                        .outbound_ciphertext,
                )?,
            )?,
        };
        let inbound_digest = match input.inbound_token {
            Some(token) => Sha256::digest(token.as_bytes()).to_vec(),
            None => existing
                .ok_or(Error::Invalid("inbound_token"))?
                .inbound_digest
                .clone(),
        };
        if Sha256::digest(outbound.as_bytes()).as_slice() == inbound_digest.as_slice() {
            return Err(Error::Invalid("tokens_must_differ"));
        }
        let row = StoredAccountProvider {
            id,
            slug: input.slug,
            name: input.name.trim().to_owned(),
            adapter: input.adapter,
            base_url,
            allowed_client_ids: input.allowed_client_ids,
            enabled: input.enabled,
            version: input
                .expected_version
                .checked_add(1)
                .ok_or(Error::Conflict)?,
            outbound_ciphertext: SecretManager::encode(
                &self
                    .secrets
                    .encrypt_for(SecretContext::AccountProvider(id), &outbound)?,
            ),
            inbound_digest,
        };
        let summary = row.summary();
        if let Some(position) = position {
            rows[position] = row;
        } else {
            rows.push(row);
        }
        persist_registry(&mut tx, &rows).await?;
        audit.record_in_transaction(&mut tx, event).await?;
        tx.commit().await?;
        Ok(summary)
    }

    /// One-time import only. Even an empty persisted registry supersedes env.
    pub async fn import_legacy_account_provider(
        &self,
        config: &crate::config::CltermuxConfig,
    ) -> Result<(), Error> {
        let mut tx = self.pool.begin().await?;
        crate::sqlx::query(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, NULL)
            ON CONFLICT (setting_key) DO NOTHING",
        )
        .bind(ACCOUNT_PROVIDERS_KEY)
        .execute(&mut *tx)
        .await?;
        let raw = repository::lock_text(&mut *tx, ACCOUNT_PROVIDERS_KEY).await?;
        if raw.is_some() {
            tx.commit().await?;
            return Ok(());
        }
        validate_metadata(
            "cltermux",
            "CLtermux",
            config.base_url.as_str(),
            &config.allowed_client_ids,
        )?;
        let id = Uuid::new_v4();
        let row = StoredAccountProvider {
            id,
            slug: "cltermux".to_owned(),
            name: "CLtermux".to_owned(),
            adapter: AccountAdapter::Cltermux,
            base_url: config.base_url.to_string(),
            allowed_client_ids: config.allowed_client_ids.clone(),
            enabled: true,
            version: 1,
            outbound_ciphertext: SecretManager::encode(
                &self
                    .secrets
                    .encrypt_for(SecretContext::AccountProvider(id), &config.outbound_token)?,
            ),
            inbound_digest: config.inbound_token_digest.clone(),
        };
        persist_registry(&mut tx, &[row]).await?;
        tx.commit().await?;
        Ok(())
    }
}

pub(crate) async fn lock_registry(
    tx: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
) -> Result<Vec<StoredAccountProvider>, Error> {
    crate::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, '[]')
        ON CONFLICT (setting_key) DO NOTHING",
    )
    .bind(ACCOUNT_PROVIDERS_KEY)
    .execute(&mut **tx)
    .await?;
    decode(
        repository::lock_text(&mut **tx, ACCOUNT_PROVIDERS_KEY)
            .await?
            .as_deref(),
    )
}

async fn persist_registry(
    tx: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    rows: &[StoredAccountProvider],
) -> Result<(), Error> {
    let raw = serde_json::to_string(rows).map_err(|_| Error::Unavailable)?;
    repository::set_text(&mut **tx, ACCOUNT_PROVIDERS_KEY, Some(&raw)).await?;
    Ok(())
}
