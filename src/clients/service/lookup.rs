//! OAuth client lookup use cases.

use super::{ClientService, ClientServiceError};
use crate::clients::repository;
use crate::oauth::authorization::RegisteredClient as OAuthRegisteredClient;

impl ClientService {
    pub async fn find_registered(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthRegisteredClient>, ClientServiceError> {
        let Some(client) = repository::find_client_by_id(&self.pool, client_id).await? else {
            return Ok(None);
        };
        if client.status != "active" {
            return Ok(None);
        }
        Ok(Some(OAuthRegisteredClient {
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            owner_user_id: client.owner_user_id,
            logo_uri: client.logo_uri,
            client_uri: client.client_uri,
        }))
    }
}
