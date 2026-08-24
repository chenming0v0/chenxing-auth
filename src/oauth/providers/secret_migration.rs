use thiserror::Error;

use super::{
    repository,
    secrets::{SecretContext, SecretError, SecretManager},
};

#[derive(Debug, Error)]
pub enum SecretMigrationError {
    #[error("database operation failed while migrating persisted credentials")]
    Database(#[from] crate::sqlx::Error),
    #[error("persisted credential migration failed: {0}")]
    Secret(#[from] SecretError),
}

/// Upgrade legacy context-free credentials and verify every current envelope before startup.
///
/// Provider rows and the SMTP setting are locked and rewritten in one transaction. A current
/// envelope that was copied to another provider or credential class therefore fails startup
/// instead of being treated as legacy data or reaching an external service.
pub async fn migrate_persisted_credentials(
    pool: &crate::sqlx::PgPool,
    secrets: &SecretManager,
) -> Result<(), SecretMigrationError> {
    let mut transaction = pool.begin().await?;

    for (provider_id, ciphertext) in
        repository::lock_client_secret_ciphertexts(&mut transaction).await?
    {
        if let Some(migrated) =
            secrets.migrate_legacy_for(SecretContext::Provider(provider_id), &ciphertext)?
        {
            let _ = repository::update_client_secret_ciphertext(
                &mut transaction,
                provider_id,
                &migrated,
            )
            .await?;
        }
    }

    if let Some(mut smtp) =
        crate::settings::repository::lock_smtp_for_secret_migration(&mut transaction).await?
        && let Some(encoded) = smtp
            .password_ciphertext
            .as_deref()
            .filter(|value| !value.is_empty())
    {
        let ciphertext = SecretManager::decode(encoded)?;
        if let Some(migrated) = secrets.migrate_legacy_for(SecretContext::Smtp, &ciphertext)? {
            smtp.password_ciphertext = Some(SecretManager::encode(&migrated));
            crate::settings::repository::set_smtp(&mut *transaction, &smtp).await?;
        }
    }

    transaction.commit().await?;
    Ok(())
}
