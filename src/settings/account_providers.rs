//! Persistent business-provider registry. Stored separately from upstream OAuth.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::oauth::providers::endpoint_policy::{EndpointPolicy, validate_endpoint_url};

pub const ACCOUNT_PROVIDERS_KEY: &str = "account_providers";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountAdapter {
    Cltermux,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountProviderSummary {
    pub slug: String,
    pub name: String,
    pub adapter: AccountAdapter,
    pub base_url: String,
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
    pub version: i64,
    pub outbound_token_configured: bool,
    pub inbound_token_configured: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountProviderInput {
    pub slug: String,
    pub name: String,
    pub adapter: AccountAdapter,
    pub base_url: String,
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
    /// Zero creates a provider; positive values update a matching version.
    pub expected_version: i64,
    pub outbound_token: Option<String>,
    pub inbound_token: Option<String>,
}

impl std::fmt::Debug for AccountProviderInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountProviderInput")
            .field("slug", &self.slug)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredAccountProvider {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub adapter: AccountAdapter,
    pub base_url: String,
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
    pub version: i64,
    pub outbound_ciphertext: String,
    pub inbound_digest: Vec<u8>,
}

impl StoredAccountProvider {
    pub fn summary(&self) -> AccountProviderSummary {
        AccountProviderSummary {
            slug: self.slug.clone(),
            name: self.name.clone(),
            adapter: self.adapter,
            base_url: self.base_url.clone(),
            allowed_client_ids: self.allowed_client_ids.clone(),
            enabled: self.enabled,
            version: self.version,
            outbound_token_configured: !self.outbound_ciphertext.is_empty(),
            inbound_token_configured: self.inbound_digest.len() == 32,
        }
    }
}

pub struct RuntimeAccountProvider {
    pub slug: String,
    pub name: String,
    pub version: i64,
    pub config: crate::config::CltermuxConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountProviderError {
    #[error("invalid account provider field: {0}")]
    Invalid(&'static str),
    #[error("provider changed; reload and retry")]
    Conflict,
    #[error("client ID already belongs to another provider")]
    ClientConflict,
    #[error("provider registry is unavailable")]
    Unavailable,
    #[error(transparent)]
    Database(#[from] crate::sqlx::Error),
    #[error(transparent)]
    Secret(#[from] crate::oauth::providers::secrets::SecretError),
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
    #[error(transparent)]
    ManagementActor(#[from] crate::users::ManagementActorValidationError),
}

pub fn valid_provider_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
}

pub(crate) fn validate_metadata(
    slug: &str,
    name: &str,
    base_url: &str,
    ids: &[String],
) -> Result<(), AccountProviderError> {
    use AccountProviderError::Invalid;
    if !valid_provider_slug(slug) {
        return Err(Invalid("slug"));
    }
    if name.trim().is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        return Err(Invalid("name"));
    }
    if base_url.len() > 2048 {
        return Err(Invalid("base_url"));
    }
    let url = url::Url::parse(base_url).map_err(|_| Invalid("base_url"))?;
    if url.scheme() != "https"
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || validate_endpoint_url(&url, EndpointPolicy::PRODUCTION).is_err()
    {
        return Err(Invalid("base_url"));
    }
    if ids.is_empty() || ids.len() > 100 {
        return Err(Invalid("allowed_client_ids"));
    }
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        if id.is_empty()
            || id.len() > 128
            || id.chars().any(|c| c.is_whitespace() || c.is_control())
            || !seen.insert(id)
        {
            return Err(Invalid("allowed_client_ids"));
        }
    }
    Ok(())
}

pub(crate) fn decode(
    raw: Option<&str>,
) -> Result<Vec<StoredAccountProvider>, AccountProviderError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let rows: Vec<StoredAccountProvider> =
        serde_json::from_str(raw).map_err(|_| AccountProviderError::Unavailable)?;
    let mut slugs = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    let mut clients = std::collections::HashSet::new();
    if rows.len() > 100 {
        return Err(AccountProviderError::Unavailable);
    }
    for row in &rows {
        validate_metadata(&row.slug, &row.name, &row.base_url, &row.allowed_client_ids)
            .map_err(|_| AccountProviderError::Unavailable)?;
        if row.version < 1
            || row.inbound_digest.len() != 32
            || row.outbound_ciphertext.is_empty()
            || !slugs.insert(&row.slug)
            || !ids.insert(row.id)
            || row.allowed_client_ids.iter().any(|id| !clients.insert(id))
        {
            return Err(AccountProviderError::Unavailable);
        }
    }
    Ok(rows)
}

/// Before generating a key, even disabled business providers count as persisted secrets.
pub(crate) async fn has_ciphertext(pool: &crate::sqlx::PgPool) -> Result<bool, crate::sqlx::Error> {
    let raw = super::repository::get_text(pool, ACCOUNT_PROVIDERS_KEY).await?;
    decode(raw.as_deref())
        .map(|rows| !rows.is_empty())
        .map_err(|_| crate::sqlx::Error::Protocol("invalid business provider registry".to_owned()))
}
