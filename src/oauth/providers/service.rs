use std::time::Duration;

use super::{
    domain::{
        ClientAuthMethod, ExternalUser, ProviderInput, ProviderRecord, ProviderSummary,
        ProviderValidationError,
    },
    repository::{self, CreateIdentityError},
    secrets::{SecretError, SecretManager},
};
use crate::users::domain::UserId;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use thiserror::Error;

const EXTERNAL_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ExternalOAuthService {
    pool: crate::sqlx::PgPool,
    secrets: SecretManager,
    http: Client,
}

#[derive(Debug, Error)]
pub enum ExternalOAuthError {
    #[error("provider input is invalid: {0}")]
    Validation(#[from] ProviderValidationError),
    #[error("provider secret operation failed: {0}")]
    Secret(#[from] SecretError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("provider was not found")]
    NotFound,
    #[error("provider is disabled")]
    Disabled,
    #[error("provider secret is not configured")]
    MissingSecret,
    #[error("external provider request failed")]
    RemoteRequest,
    #[error("external provider returned invalid user information")]
    InvalidUserInfo,
    #[error("external email is already registered")]
    EmailAlreadyRegistered,
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required")]
    OwnerBootstrapRequired,
}

#[derive(Debug, Clone)]
pub struct ExternalToken {
    pub access_token: String,
    pub token_type: Option<String>,
}

impl ExternalOAuthService {
    pub fn new(
        pool: crate::sqlx::PgPool,
        secrets: SecretManager,
    ) -> Result<Self, ExternalOAuthError> {
        let http = Client::builder()
            .timeout(EXTERNAL_HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        Ok(Self {
            pool,
            secrets,
            http,
        })
    }

    pub async fn list(&self) -> Result<Vec<ProviderSummary>, ExternalOAuthError> {
        Ok(repository::list_providers(&self.pool)
            .await?
            .into_iter()
            .map(|provider| provider.summary())
            .collect())
    }

    pub async fn find(&self, slug: &str) -> Result<ProviderRecord, ExternalOAuthError> {
        repository::find_by_slug(&self.pool, slug)
            .await?
            .ok_or(ExternalOAuthError::NotFound)
    }

    pub async fn create(
        &self,
        input: ProviderInput,
    ) -> Result<ProviderSummary, ExternalOAuthError> {
        let validated = input.validate()?;
        let ciphertext = self.encrypt_secret(validated.client_secret.as_deref())?;
        Ok(
            repository::insert_provider(&self.pool, &validated, ciphertext)
                .await?
                .summary(),
        )
    }

    pub async fn update(
        &self,
        slug: &str,
        input: ProviderInput,
    ) -> Result<bool, ExternalOAuthError> {
        let validated = input.validate()?;
        let ciphertext = match validated.client_secret.as_deref() {
            Some(secret) => self.encrypt_secret(Some(secret))?,
            None => self.find(slug).await?.client_secret_ciphertext,
        };
        Ok(repository::update_provider(&self.pool, slug, &validated, ciphertext).await?)
    }

    pub async fn set_status(&self, slug: &str, status: &str) -> Result<bool, ExternalOAuthError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        Ok(repository::set_status(&self.pool, slug, status).await?)
    }

    pub fn authorization_url(
        &self,
        provider: &ProviderRecord,
        callback_uri: &str,
        state: &str,
    ) -> Result<String, ExternalOAuthError> {
        let mut url = provider.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &provider.client_id);
            query.append_pair("redirect_uri", callback_uri);
            query.append_pair("scope", &provider.scopes.join(" "));
            query.append_pair("state", state);
        }
        Ok(url.to_string())
    }

    pub async fn exchange_code(
        &self,
        provider: &ProviderRecord,
        callback_uri: &str,
        code: &str,
    ) -> Result<ExternalToken, ExternalOAuthError> {
        let secret = self.decrypt_secret(provider)?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", callback_uri),
        ];
        let request = match provider.client_auth_method {
            ClientAuthMethod::Basic => self
                .http
                .post(provider.token_endpoint.clone())
                .basic_auth(&provider.client_id, Some(secret))
                .form(&form),
            ClientAuthMethod::RequestBody => {
                form.push(("client_id", provider.client_id.as_str()));
                form.push(("client_secret", secret.as_str()));
                self.http.post(provider.token_endpoint.clone()).form(&form)
            }
        };
        let response = request
            .send()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        if response.status() != StatusCode::OK {
            return Err(ExternalOAuthError::RemoteRequest);
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ExternalOAuthError::RemoteRequest)?;
        Ok(ExternalToken {
            access_token: access_token.to_owned(),
            token_type: payload
                .get("token_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    pub async fn userinfo(
        &self,
        provider: &ProviderRecord,
        token: &ExternalToken,
    ) -> Result<ExternalUser, ExternalOAuthError> {
        let response = self
            .http
            .get(provider.userinfo_endpoint.clone())
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        if response.status() != StatusCode::OK {
            return Err(ExternalOAuthError::RemoteRequest);
        }
        let claims: Value = response
            .json()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        let validated = ProviderInput {
            name: provider.name.clone(),
            slug: provider.slug.clone(),
            authorization_endpoint: provider.authorization_endpoint.to_string(),
            token_endpoint: provider.token_endpoint.to_string(),
            userinfo_endpoint: provider.userinfo_endpoint.to_string(),
            client_id: provider.client_id.clone(),
            client_secret: None,
            scopes: provider.scopes.clone(),
            subject_claim: provider.subject_claim.clone(),
            email_claim: provider.email_claim.clone(),
            name_claim: provider.name_claim.clone(),
            email_verified_claim: provider.email_verified_claim.clone(),
            client_auth_method: provider.client_auth_method,
        }
        .validate()?;
        ExternalUser::from_claims(&claims, &validated)
            .map_err(|_| ExternalOAuthError::InvalidUserInfo)
    }

    pub async fn resolve_user(
        &self,
        provider: &ProviderRecord,
        external: &ExternalUser,
    ) -> Result<UserId, ExternalOAuthError> {
        if let Some(identity) =
            repository::find_identity(&self.pool, provider.id, &external.subject).await?
        {
            if identity.user_status != "active" {
                return Err(ExternalOAuthError::UserDisabled);
            }
            return Ok(identity.user_id);
        }
        let password_hash =
            unusable_password_hash().map_err(|_| ExternalOAuthError::RemoteRequest)?;
        repository::create_user_with_identity(
            &self.pool,
            provider.id,
            &external.email,
            external.name.as_deref(),
            &external.subject,
            &password_hash,
        )
        .await
        .map_err(|error| match error {
            CreateIdentityError::EmailAlreadyRegistered => {
                ExternalOAuthError::EmailAlreadyRegistered
            }
            CreateIdentityError::UserDisabled => ExternalOAuthError::UserDisabled,
            CreateIdentityError::OwnerBootstrapRequired => {
                ExternalOAuthError::OwnerBootstrapRequired
            }
            CreateIdentityError::Database(error) => ExternalOAuthError::Database(error),
        })
    }

    fn encrypt_secret(&self, secret: Option<&str>) -> Result<Vec<u8>, ExternalOAuthError> {
        secret
            .map(|secret| self.secrets.encrypt(secret))
            .transpose()
            .map(|value| value.unwrap_or_default())
            .map_err(Into::into)
    }

    fn decrypt_secret(&self, provider: &ProviderRecord) -> Result<String, ExternalOAuthError> {
        if provider.client_secret_ciphertext.is_empty() {
            return Err(ExternalOAuthError::MissingSecret);
        }
        self.secrets
            .decrypt(&provider.client_secret_ciphertext)
            .map_err(Into::into)
    }
}

fn unusable_password_hash() -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(
            URL_SAFE_NO_PAD
                .encode(rand::random::<[u8; 32]>())
                .as_bytes(),
            &salt,
        )
        .map(|hash| hash.to_string())
}
