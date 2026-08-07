//! Client registration use cases.

use super::{ClientService, ClientServiceError, RegisteredClientSecret};
use crate::clients::{
    credentials::{issue_client_credential, ClientRegistrationRequest},
    domain::validate_client_registration_with_limits,
    repository::{self, ClientInsertError},
};
use crate::users::domain::UserId;
use uuid::Uuid;

impl ClientService {
    pub async fn register(
        &self,
        input: impl Into<ClientRegistrationRequest>,
    ) -> Result<RegisteredClientSecret, ClientServiceError> {
        let request = input.into();
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let (credential, client_secret) = issue_client_credential(auth_method)?;
        let client =
            repository::insert_client(&self.pool, registration, client_id, credential).await?;

        Ok(registered_client_secret(client, client_secret))
    }

    pub async fn register_for_user(
        &self,
        owner_user_id: UserId,
        input: impl Into<ClientRegistrationRequest>,
        oauth_clients_limit: i64,
    ) -> Result<RegisteredClientSecret, ClientServiceError> {
        let request = input.into();
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let (credential, client_secret) = issue_client_credential(auth_method)?;
        let client = repository::insert_owned_client(
            &self.pool,
            owner_user_id,
            registration,
            client_id,
            credential,
            oauth_clients_limit,
        )
        .await
        .map_err(|error| match error {
            ClientInsertError::QuotaExceeded => ClientServiceError::QuotaExceeded,
            ClientInsertError::Database(error) => ClientServiceError::Database(error),
        })?;

        Ok(registered_client_secret(client, client_secret))
    }
}

fn registered_client_secret(
    client: repository::NewClient,
    client_secret: Option<String>,
) -> RegisteredClientSecret {
    RegisteredClientSecret {
        id: client.id,
        client_id: client.client_id,
        client_secret,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        scopes: client.scopes,
        auth_method: client.auth_method,
    }
}
