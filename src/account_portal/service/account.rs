use uuid::Uuid;

use crate::users::domain::UserId;

use super::AccountPortalService;
use crate::account_portal::bundle::TokenBundle;
use crate::account_portal::service_error::ServiceError;
use crate::account_portal::views::BindingView;

impl AccountPortalService {
    /// 向提供方拉取最新快照。网络失败时返回本地缓存，不使令牌失效。
    pub async fn sync_binding(
        &self,
        user_id: UserId,
        binding_id: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let binding = self
            .store
            .get_binding(binding_id)
            .await?
            .ok_or(ServiceError::BindingNotFound)?;
        if binding.user_id != user_id || !binding.is_live() {
            return Err(ServiceError::BindingNotFound);
        }
        let Some(provider) = self.store.get_provider(binding.provider_id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        let Some(ciphertext) = binding.token_bundle_ciphertext.as_deref() else {
            return Ok(BindingView::from_row(&binding));
        };
        let plaintext = match self.decrypt_bundle(provider.id, binding.id, ciphertext) {
            Ok(value) => value,
            Err(_) => return Ok(BindingView::from_row(&binding)),
        };
        let bundle = match TokenBundle::parse(plaintext.expose().as_bytes()) {
            Ok(value) => value,
            Err(_) => return Ok(BindingView::from_row(&binding)),
        };
        let client = self.provider_client(&provider)?;
        match client.account(&bundle.access_token, &binding.uid).await {
            Ok(snapshot) => {
                let mut cached = binding.clone();
                cached.snapshot_json = snapshot.to_value();
                Ok(BindingView::from_row(&cached))
            }
            Err(_) => Ok(BindingView::from_row(&binding)),
        }
    }
}
