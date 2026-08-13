use thiserror::Error;

use super::repository;
use crate::config::{Config, ConfigError, normalize_issuer_url};

pub const APP_ISSUER_KEY: &str = "app_issuer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializeIssuerOutcome {
    Created,
    AlreadyConfigured,
    Conflict,
}

#[derive(Debug, Error)]
pub enum IssuerSettingError {
    #[error("persisted issuer configuration is invalid")]
    Invalid(#[from] ConfigError),
    #[error("could not read or persist issuer configuration")]
    Database(#[from] crate::sqlx::Error),
}

pub async fn load(pool: &crate::sqlx::PgPool) -> Result<Option<String>, IssuerSettingError> {
    repository::get_text(pool, APP_ISSUER_KEY)
        .await?
        .filter(|value| !value.trim().is_empty())
        .map(|value| normalize_issuer_url(&value))
        .transpose()
        .map_err(IssuerSettingError::from)
}

/// 首次写入固定 Issuer。相同值可重复执行，不同值必须走明确的数据迁移流程。
pub async fn initialize(
    pool: &crate::sqlx::PgPool,
    value: &str,
) -> Result<InitializeIssuerOutcome, IssuerSettingError> {
    let value = normalize_issuer_url(value)?;
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341929)")
        .execute(&mut *transaction)
        .await?;

    if let Some(existing) = repository::get_text(&mut *transaction, APP_ISSUER_KEY)
        .await?
        .filter(|existing| !existing.trim().is_empty())
    {
        let existing = normalize_issuer_url(&existing)?;
        transaction.rollback().await?;
        return Ok(if existing == value {
            InitializeIssuerOutcome::AlreadyConfigured
        } else {
            InitializeIssuerOutcome::Conflict
        });
    }

    repository::set_text(&mut *transaction, APP_ISSUER_KEY, Some(&value)).await?;
    transaction.commit().await?;
    Ok(InitializeIssuerOutcome::Created)
}

/// 数据库是运行期唯一事实来源。APP_ISSUER 只负责旧部署第一次升级时的导入。
pub async fn resolve(
    config: &mut Config,
    pool: &crate::sqlx::PgPool,
) -> Result<(), IssuerSettingError> {
    let environment_value = config
        .configured_issuer()
        .map(str::to_owned)
        .or_else(|| config.take_legacy_issuer_import());

    if let Some(persisted) = load(pool).await? {
        if let Some(environment_value) = environment_value {
            match normalize_issuer_url(&environment_value) {
                Ok(value) if value == persisted => {}
                Ok(_) => tracing::warn!(
                    event = "issuer.environment_ignored",
                    "APP_ISSUER differs from the persisted issuer; the database value remains authoritative"
                ),
                Err(_) => tracing::warn!(
                    event = "issuer.invalid_environment_ignored",
                    "APP_ISSUER is invalid but the persisted issuer remains authoritative"
                ),
            }
        }
        config.apply_persisted_issuer(&persisted)?;
        return Ok(());
    }

    if let Some(environment_value) = environment_value {
        match initialize(pool, &environment_value).await? {
            InitializeIssuerOutcome::Created => tracing::info!(
                event = "issuer.environment_imported",
                "imported legacy APP_ISSUER into persistent settings"
            ),
            InitializeIssuerOutcome::AlreadyConfigured => {}
            InitializeIssuerOutcome::Conflict => tracing::warn!(
                event = "issuer.environment_import_conflict",
                "another instance persisted a different issuer while APP_ISSUER was being imported"
            ),
        }
        let persisted = load(pool).await?.ok_or(crate::sqlx::Error::RowNotFound)?;
        config.apply_persisted_issuer(&persisted)?;
        return Ok(());
    }

    config.issuer_configured = false;
    config.issuer_url.clear();
    tracing::warn!(
        event = "issuer.not_configured",
        "APP_ISSUER is not configured; authentication, administration and OAuth/OIDC routes are disabled"
    );
    Ok(())
}
