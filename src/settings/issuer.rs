use thiserror::Error;
use time::OffsetDateTime;

use crate::config::{Config, ConfigError, IssuerUrl};

pub const APP_ISSUER_KEY: &str = "app_issuer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRecord {
    pub value: String,
    pub generation: i64,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawIssuerRecord {
    pub value: Option<String>,
    pub generation: i64,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerWrite {
    pub previous_value: Option<String>,
    pub record: IssuerRecord,
    pub changed: bool,
}

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

pub async fn load(pool: &crate::sqlx::PgPool) -> Result<Option<IssuerRecord>, IssuerSettingError> {
    load_with(pool).await
}

pub(crate) async fn load_raw(
    pool: &crate::sqlx::PgPool,
) -> Result<Option<RawIssuerRecord>, IssuerSettingError> {
    let row = crate::sqlx::query_as::<_, (Option<String>, i64, OffsetDateTime)>(
        "SELECT setting_value, generation, updated_at
         FROM app_settings
         WHERE setting_key = 'app_issuer'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(value, generation, updated_at)| RawIssuerRecord {
        value,
        generation,
        updated_at,
    }))
}

pub(crate) async fn load_with<'e, E>(
    executor: E,
) -> Result<Option<IssuerRecord>, IssuerSettingError>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let row = crate::sqlx::query_as::<_, (Option<String>, i64, OffsetDateTime)>(
        "SELECT setting_value, generation, updated_at
         FROM app_settings
         WHERE setting_key = 'app_issuer'",
    )
    .fetch_optional(executor)
    .await?;
    row.and_then(|(value, generation, updated_at)| {
        value
            .filter(|value| !value.trim().is_empty())
            .map(|value| (value, generation, updated_at))
    })
    .map(|(value, generation, updated_at)| {
        IssuerUrl::parse(&value).map(|issuer| IssuerRecord {
            value: issuer.as_str().to_owned(),
            generation,
            updated_at,
        })
    })
    .transpose()
    .map_err(IssuerSettingError::from)
}

/// 通过数据库专用 CAS 函数写入 Issuer。调用方拥有事务边界，可在同一事务中写审计。
pub(crate) async fn set_in_transaction(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    value: &IssuerUrl,
    expected_generation: i64,
) -> Result<Option<IssuerWrite>, IssuerSettingError> {
    let row = crate::sqlx::query_as::<_, (Option<String>, String, i64, OffsetDateTime, bool)>(
        "SELECT previous_value, setting_value, generation, updated_at, changed
         FROM set_app_issuer($1, $2)",
    )
    .bind(value.as_str())
    .bind(expected_generation)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(
        |(previous_value, setting_value, generation, updated_at, changed)| IssuerWrite {
            previous_value,
            record: IssuerRecord {
                value: setting_value,
                generation,
                updated_at,
            },
            changed,
        },
    ))
}

/// 首次写入固定 Issuer。相同值可重复执行；不同值由 Owner 更新 API 显式变更。
pub async fn initialize(
    pool: &crate::sqlx::PgPool,
    value: &str,
) -> Result<InitializeIssuerOutcome, IssuerSettingError> {
    let value = IssuerUrl::parse(value)?;
    if let Some(existing) = load(pool).await? {
        return Ok(if existing.value == value.as_str() {
            InitializeIssuerOutcome::AlreadyConfigured
        } else {
            InitializeIssuerOutcome::Conflict
        });
    }

    let mut transaction = pool.begin().await?;
    let write = set_in_transaction(&mut transaction, &value, 0).await?;
    match write {
        Some(write) if write.record.value == value.as_str() => {
            transaction.commit().await?;
            Ok(if write.changed {
                InitializeIssuerOutcome::Created
            } else {
                InitializeIssuerOutcome::AlreadyConfigured
            })
        }
        _ => {
            transaction.rollback().await?;
            let existing = load(pool).await?;
            Ok(
                if existing
                    .as_ref()
                    .is_some_and(|existing| existing.value == value.as_str())
                {
                    InitializeIssuerOutcome::AlreadyConfigured
                } else {
                    InitializeIssuerOutcome::Conflict
                },
            )
        }
    }
}

/// 数据库是运行时权威；旧 APP_ISSUER 仅用于旧部署的一次性导入。
pub async fn resolve(
    config: &mut Config,
    pool: &crate::sqlx::PgPool,
) -> Result<Option<IssuerRecord>, IssuerSettingError> {
    let environment_value = config
        .configured_issuer()
        .map(|issuer| issuer.as_str().to_owned())
        .or_else(|| config.take_legacy_issuer_import());

    if let Some(persisted) = load(pool).await? {
        if let Some(environment_value) = environment_value {
            match IssuerUrl::parse(&environment_value) {
                Ok(value) if value.as_str() == persisted.value => {}
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
        config.apply_persisted_issuer(&persisted.value)?;
        return Ok(Some(persisted));
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
        config.apply_persisted_issuer(&persisted.value)?;
        return Ok(Some(persisted));
    }

    config.issuer = None;
    tracing::warn!(
        event = "issuer.not_configured",
        "no persisted issuer is configured; health, static content, and bootstrap remain available; local login is limited to user ID 1, ADMIN_TOKEN recovery remains available, and user creation plus issuer-dependent routes are disabled"
    );
    Ok(None)
}
