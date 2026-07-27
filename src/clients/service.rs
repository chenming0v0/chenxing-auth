use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::{
    domain::{ClientRegistrationError, ClientRegistrationInput, validate_client_registration},
    repository,
};
use crate::oauth::authorization::RegisteredClient as OAuthRegisteredClient;
use crate::users::credentials::verify_password;

#[derive(Clone)]
pub struct ClientService {
    pool: PgPool,
}

#[derive(Debug)]
pub struct RegisteredClientSecret {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug)]
pub struct ClientSummary {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RotatedClientSecret {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Error)]
pub enum ClientServiceError {
    #[error(transparent)]
    Validation(#[from] ClientRegistrationError),
    #[error("could not hash client secret")]
    SecretHash,
    #[error("could not persist client")]
    Database(#[from] sqlx::Error),
    #[error("client data is invalid")]
    InvalidData,
}

pub fn verify_client_secret(secret: &str, encoded_hash: &str) -> bool {
    verify_password(secret, encoded_hash)
}

impl ClientService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register(
        &self,
        input: ClientRegistrationInput,
    ) -> Result<RegisteredClientSecret, ClientServiceError> {
        let registration = validate_client_registration(input)?;
        let client_id = format!("cx_{}", Uuid::new_v4().simple());
        let client_secret = format!("cxs_{}", Uuid::new_v4().simple());
        let salt = SaltString::generate(&mut OsRng);
        let client_secret_hash = Argon2::default()
            .hash_password(client_secret.as_bytes(), &salt)
            .map_err(|_| ClientServiceError::SecretHash)?
            .to_string();
        let client =
            repository::insert_client(&self.pool, registration, client_id, client_secret_hash)
                .await?;

        Ok(RegisteredClientSecret {
            id: client.id,
            client_id: client.client_id,
            client_secret,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
        })
    }

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
        }))
    }

    pub async fn verify_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<bool, ClientServiceError> {
        let Some(client) = repository::find_client_credentials(&self.pool, client_id).await? else {
            return Ok(false);
        };
        Ok(client.status == "active"
            && verify_client_secret(client_secret, &client.client_secret_hash))
    }

    pub async fn list(&self) -> Result<Vec<ClientSummary>, ClientServiceError> {
        Ok(repository::list_clients(&self.pool)
            .await?
            .into_iter()
            .map(|client| ClientSummary {
                id: client.id,
                client_id: client.client_id,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                scopes: client.scopes,
                status: client.status,
            })
            .collect())
    }

    pub async fn update(
        &self,
        client_id: &str,
        input: ClientRegistrationInput,
    ) -> Result<bool, ClientServiceError> {
        let registration = validate_client_registration(input)?;
        Ok(repository::update_client(
            &self.pool,
            client_id,
            &registration.client_name,
            &registration.redirect_uris,
            &registration.scopes,
        )
        .await?)
    }

    pub async fn set_status(
        &self,
        client_id: &str,
        status: &str,
    ) -> Result<bool, ClientServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Err(ClientServiceError::InvalidData);
        }
        Ok(repository::set_client_status(&self.pool, client_id, status).await?)
    }

    pub async fn rotate_secret(
        &self,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let client_secret = format!("cxs_{}", Uuid::new_v4().simple());
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(client_secret.as_bytes(), &salt)
            .map_err(|_| ClientServiceError::SecretHash)?
            .to_string();
        if !repository::update_client_secret(&self.pool, client_id, &hash).await? {
            return Err(ClientServiceError::InvalidData);
        }
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }
}
