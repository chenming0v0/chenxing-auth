//! Account-provider configuration resolution for linked-account use cases.
//!
//! A provider binding can come from the dynamic settings registry or from the
//! statically configured CLtermux integration; both paths are resolved here so
//! that `service.rs` only orchestrates use cases.

use crate::{
    integrations::cltermux::{adapter::CltermuxIntegration, types::IntegrationError},
    settings::SettingsService,
};

use super::{error::LinkedAccountServiceError, views::AccountProviderView};

pub(super) const PROVIDER_SLUG: &str = "cltermux";
pub(super) const PROVIDER_NAME: &str = "CLtermux";

pub(super) async fn integration(
    cltermux: &Option<CltermuxIntegration>,
    provider_settings: &Option<SettingsService>,
    slug: &str,
) -> Result<(CltermuxIntegration, Option<i64>), LinkedAccountServiceError> {
    if let Some(settings) = provider_settings {
        let provider = settings
            .account_provider(slug)
            .await
            .map_err(|_| IntegrationError::ProviderUnavailable)?
            .ok_or(LinkedAccountServiceError::NotConfigured)?;
        return Ok((
            CltermuxIntegration::new(&provider.config)?,
            Some(provider.version),
        ));
    }
    if slug != PROVIDER_SLUG {
        return Err(LinkedAccountServiceError::NotConfigured);
    }
    Ok((
        cltermux
            .clone()
            .ok_or(LinkedAccountServiceError::NotConfigured)?,
        None,
    ))
}

pub(super) async fn descriptors(
    cltermux: &Option<CltermuxIntegration>,
    provider_settings: &Option<SettingsService>,
) -> Result<Vec<AccountProviderView>, LinkedAccountServiceError> {
    if let Some(settings) = provider_settings {
        return Ok(settings
            .account_providers()
            .await
            .map_err(|_| IntegrationError::ProviderUnavailable)?
            .into_iter()
            .filter(|provider| provider.enabled)
            .map(|provider| AccountProviderView {
                id: provider.slug,
                name: provider.name,
                icon_url: None,
                kind: "service_account".to_owned(),
                binding_method: "credentials".to_owned(),
                can_refresh: true,
            })
            .collect());
    }
    Ok(cltermux
        .as_ref()
        .map(|_| {
            vec![AccountProviderView {
                id: PROVIDER_SLUG.to_owned(),
                name: PROVIDER_NAME.to_owned(),
                icon_url: None,
                kind: "service_account".to_owned(),
                binding_method: "credentials".to_owned(),
                can_refresh: true,
            }]
        })
        .unwrap_or_default())
}
