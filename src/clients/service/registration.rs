//! Client registration use cases.

use super::{ClientService, ClientServiceError, RegisteredClientSecret, RegisteredOwnedClient};
use crate::clients::{
    credentials::{ClientRegistrationRequest, hash_client_secret, issue_client_credential},
    domain::validate_client_registration_with_limits,
    idempotency::{ClientIdempotencyContext, ClientIdempotencyError, IdempotencyKey},
    repository::{self, ClientInsertError, IdempotentClientOperationError},
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

    pub async fn register_with_audit<F>(
        &self,
        input: impl Into<ClientRegistrationRequest>,
        audit_event: F,
    ) -> Result<RegisteredClientSecret, ClientServiceError>
    where
        F: FnOnce(&repository::NewClient) -> crate::audit::AuditEvent,
    {
        let request = input.into();
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let (credential, client_secret) = issue_client_credential(auth_method)?;
        let client = repository::insert_client_with_audit(
            &self.pool,
            registration,
            client_id,
            credential,
            audit_event,
        )
        .await
        .map_err(|error| match error {
            repository::AuditedClientInsertError::QuotaExceeded => {
                ClientServiceError::QuotaExceeded
            }
            repository::AuditedClientInsertError::Database(error) => {
                ClientServiceError::Database(error)
            }
            repository::AuditedClientInsertError::Audit(error) => {
                tracing::error!(event = "client_create.audit_unavailable", error = %error);
                ClientServiceError::AuditUnavailable
            }
        })?;
        Ok(registered_client_secret(client, client_secret))
    }

    pub async fn register_for_user(
        &self,
        owner_user_id: UserId,
        input: impl Into<ClientRegistrationRequest>,
    ) -> Result<Option<RegisteredOwnedClient>, ClientServiceError> {
        let request = input.into();
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let (credential, client_secret) = issue_client_credential(auth_method)?;
        let Some(owned_client) = repository::insert_owned_client(
            &self.pool,
            owner_user_id,
            registration,
            client_id,
            credential,
        )
        .await
        .map_err(|error| match error {
            ClientInsertError::QuotaExceeded => ClientServiceError::QuotaExceeded,
            ClientInsertError::Database(error) => ClientServiceError::Database(error),
        })?
        else {
            return Ok(None);
        };

        Ok(Some(RegisteredOwnedClient {
            client: registered_client_secret(owned_client.client, client_secret),
            quota_limits: owned_client.quota_limits,
        }))
    }

    pub async fn register_for_user_with_audit<F>(
        &self,
        owner_user_id: UserId,
        input: impl Into<ClientRegistrationRequest>,
        audit_event: F,
    ) -> Result<Option<RegisteredOwnedClient>, ClientServiceError>
    where
        F: FnOnce(&repository::NewClient) -> crate::audit::AuditEvent,
    {
        let request = input.into();
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let (credential, client_secret) = issue_client_credential(auth_method)?;
        let Some(owned_client) = repository::insert_owned_client_with_audit(
            &self.pool,
            owner_user_id,
            registration,
            client_id,
            credential,
            audit_event,
        )
        .await
        .map_err(|error| match error {
            repository::AuditedClientInsertError::QuotaExceeded => {
                ClientServiceError::QuotaExceeded
            }
            repository::AuditedClientInsertError::Database(error) => {
                ClientServiceError::Database(error)
            }
            repository::AuditedClientInsertError::Audit(error) => {
                tracing::error!(event = "client_create.audit_unavailable", error = %error);
                ClientServiceError::AuditUnavailable
            }
        })?
        else {
            return Ok(None);
        };
        Ok(Some(RegisteredOwnedClient {
            client: registered_client_secret(owned_client.client, client_secret),
            quota_limits: owned_client.quota_limits,
        }))
    }

    pub async fn register_with_audit_idempotent<F>(
        &self,
        input: impl Into<ClientRegistrationRequest>,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: F,
    ) -> Result<RegisteredClientSecret, ClientServiceError>
    where
        F: FnOnce(&repository::NewClient) -> crate::audit::AuditEvent,
    {
        self.register_idempotent(None, input.into(), actor_scope, key, audit_event)
            .await
    }

    pub async fn register_for_user_with_audit_idempotent<F>(
        &self,
        owner_user_id: UserId,
        input: impl Into<ClientRegistrationRequest>,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: F,
    ) -> Result<RegisteredClientSecret, ClientServiceError>
    where
        F: FnOnce(&repository::NewClient) -> crate::audit::AuditEvent,
    {
        self.register_idempotent(
            Some(owner_user_id),
            input.into(),
            actor_scope,
            key,
            audit_event,
        )
        .await
    }

    async fn register_idempotent<F>(
        &self,
        owner_user_id: Option<UserId>,
        request: ClientRegistrationRequest,
        actor_scope: String,
        key: IdempotencyKey,
        audit_event: F,
    ) -> Result<RegisteredClientSecret, ClientServiceError>
    where
        F: FnOnce(&repository::NewClient) -> crate::audit::AuditEvent,
    {
        let auth_method = request.auth_method;
        let registration =
            validate_client_registration_with_limits(request.registration, &self.limits)?;
        let context =
            ClientIdempotencyContext::for_create(actor_scope, key, &registration, auth_method);
        let keys = self
            .idempotency_keys
            .as_ref()
            .ok_or(ClientServiceError::IdempotencyKeyUnavailable)?;
        let active_kid = keys.active_kid().to_owned();
        let client_secret = match auth_method {
            crate::clients::domain::ClientAuthMethod::None => None,
            crate::clients::domain::ClientAuthMethod::Basic
            | crate::clients::domain::ClientAuthMethod::Post => Some(
                context
                    .derive_secret(keys, &active_kid)
                    .map_err(map_idempotency_crypto_error)?,
            ),
        };
        let credential = match (&client_secret, auth_method) {
            (Some(secret), crate::clients::domain::ClientAuthMethod::Basic) => {
                repository::ClientCredential::SecretBasic(hash_client_secret(secret)?)
            }
            (Some(secret), crate::clients::domain::ClientAuthMethod::Post) => {
                repository::ClientCredential::SecretPost(hash_client_secret(secret)?)
            }
            (None, crate::clients::domain::ClientAuthMethod::None) => {
                repository::ClientCredential::Public
            }
            _ => return Err(ClientServiceError::IdempotencyCorruptResult),
        };
        let client_id = format!("cx_{}", uuid::Uuid::new_v4().simple());
        let persisted = repository::insert_client_idempotent_with_audit(
            &self.pool,
            repository::IdempotentClientInsert {
                owner_user_id,
                registration,
                client_id,
                credential,
                context: &context,
                active_secret_kid: &active_kid,
                audit_event,
            },
        )
        .await
        .map_err(map_idempotency_repository_error)?;
        let auth_method =
            crate::clients::domain::ClientAuthMethod::parse(&persisted.value.auth_method)
                .ok_or(ClientServiceError::IdempotencyCorruptResult)?;
        let client_secret = match auth_method {
            crate::clients::domain::ClientAuthMethod::None => None,
            crate::clients::domain::ClientAuthMethod::Basic
            | crate::clients::domain::ClientAuthMethod::Post => Some(
                context
                    .derive_secret(keys, &persisted.secret_kid)
                    .map_err(map_idempotency_crypto_error)?,
            ),
        };
        Ok(RegisteredClientSecret {
            id: persisted.value.id,
            client_id: persisted.value.client_id,
            client_name: persisted.value.client_name,
            redirect_uris: persisted.value.redirect_uris,
            scopes: persisted.value.scopes,
            auth_method,
            client_secret,
            logo_uri: persisted.value.logo_uri,
            client_uri: persisted.value.client_uri,
        })
    }
}

fn map_idempotency_crypto_error(error: ClientIdempotencyError) -> ClientServiceError {
    match error {
        ClientIdempotencyError::UnknownKeyId => ClientServiceError::IdempotencyKeyUnavailable,
        ClientIdempotencyError::InvalidKey => ClientServiceError::IdempotencyKeyInvalid,
    }
}

fn map_idempotency_repository_error(error: IdempotentClientOperationError) -> ClientServiceError {
    match error {
        IdempotentClientOperationError::QuotaExceeded => ClientServiceError::QuotaExceeded,
        IdempotentClientOperationError::IdempotencyConflict => {
            ClientServiceError::IdempotencyConflict
        }
        IdempotentClientOperationError::CorruptResult => {
            ClientServiceError::IdempotencyCorruptResult
        }
        IdempotentClientOperationError::Database(error) => ClientServiceError::Database(error),
        IdempotentClientOperationError::Audit(error) => {
            tracing::error!(event = "client_create.audit_unavailable", error = %error);
            ClientServiceError::AuditUnavailable
        }
        IdempotentClientOperationError::MutationConflict => {
            ClientServiceError::IdempotencyCorruptResult
        }
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
        logo_uri: client.logo_uri,
        client_uri: client.client_uri,
    }
}
