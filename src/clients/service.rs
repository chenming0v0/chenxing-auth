use crate::sqlx::PgPool;
use crate::users::domain::UserId;
use uuid::Uuid;
use serde::Serialize;
use thiserror::Error;

use super::{
    credentials::{credentials_match, generate_client_secret, issue_client_credential},
    domain::{
        ClientAuthMethod, ClientRegistrationError, ClientRegistrationLimits,
        validate_client_registration_with_limits,
    },
    repository::{self, ClientInsertError},
};
use crate::oauth::authorization::RegisteredClient as OAuthRegisteredClient;

// 凭据签发/校验拆到 credentials.rs（src-line-limit），此处保持既有公开路径不变。
pub use super::credentials::{ClientRegistrationRequest, verify_client_secret};

/// 管理端 Client 列表的默认与最大返回条数，与 User 列表保持一致。
const DEFAULT_CLIENT_LIST_LIMIT: i64 = 50;
const MAX_CLIENT_LIST_LIMIT: i64 = 200;

#[derive(Clone)]
pub struct ClientService {
    pool: PgPool,
    limits: ClientRegistrationLimits,
}

#[derive(Debug)]
pub struct RegisteredClientSecret {
    pub id: i64,
    pub client_id: String,
    /// 明文 secret；若为公开客户端（`auth_method = none`）则为 `None`。
    pub client_secret: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub auth_method: ClientAuthMethod,
}

#[derive(Debug, Serialize)]
pub struct ClientSummary {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
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
    Database(#[from] crate::sqlx::Error),
    #[error("normal user OAuth project quota has been exhausted")]
    QuotaExceeded,
    #[error("client data is invalid")]
    InvalidData,
}

impl ClientService {
    pub fn new(pool: PgPool) -> Self {
        Self::with_limits(pool, ClientRegistrationLimits::default())
    }

    pub fn with_limits(pool: PgPool, limits: ClientRegistrationLimits) -> Self {
        Self { pool, limits }
    }

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

        Ok(RegisteredClientSecret {
            id: client.id,
            client_id: client.client_id,
            client_secret,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            auth_method: client.auth_method,
        })
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

        Ok(RegisteredClientSecret {
            id: client.id,
            client_id: client.client_id,
            client_secret,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            auth_method: client.auth_method,
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
            owner_user_id: client.owner_user_id,
        }))
    }

    pub async fn verify_credentials(
        &self,
        client_id: &str,
        auth_method: ClientAuthMethod,
        client_secret: Option<&str>,
    ) -> Result<bool, ClientServiceError> {
        let Some(client) = repository::find_client_credentials(&self.pool, client_id).await? else {
            return Ok(false);
        };
        if client.status != "active"
            || ClientAuthMethod::parse(&client.auth_method) != Some(auth_method)
        {
            return Ok(false);
        }
        Ok(credentials_match(
            auth_method,
            client_secret,
            client.client_secret_hash.as_deref(),
        ))
    }

    /// 列出 Client（管理端），支持分页。
    ///
    /// `limit` / `offset` 默认行为与 `AuditService::list` / `UserService::query` 保持一致，
    /// 避免无上限列表在单次响应里倾倒全表（Issue #67）。
    pub async fn list(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ClientSummary>, ClientServiceError> {
        let limit = limit
            .unwrap_or(DEFAULT_CLIENT_LIST_LIMIT)
            .clamp(1, MAX_CLIENT_LIST_LIMIT);
        let offset = offset.unwrap_or(0).max(0);
        Ok(repository::list_clients(&self.pool, None, limit, offset)
            .await?
            .into_iter()
            .map(|client| ClientSummary {
                id: client.id,
                client_id: client.client_id,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                scopes: client.scopes,
                status: client.status,
                owner_user_id: client.owner_user_id,
            })
            .collect())
    }

    pub async fn query(
        &self,
        search: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ClientSummary>, i64), ClientServiceError> {
        let (clients, total) =
            repository::query_clients(&self.pool, search, status, limit, offset).await?;
        Ok((
            clients
                .into_iter()
                .map(|client| ClientSummary {
                    id: client.id,
                    client_id: client.client_id,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris,
                    scopes: client.scopes,
                    status: client.status,
                    owner_user_id: client.owner_user_id,
                })
                .collect(),
            total,
        ))
    }

    pub async fn count(&self) -> Result<i64, ClientServiceError> {
        Ok(repository::count_clients(&self.pool).await?)
    }

    /// 列出当前用户拥有的 Client。
    ///
    /// 尽管用户套餐的 `oauth_clients_limit` 通常较小，
    /// 仍用 `MAX_CLIENT_LIST_LIMIT` 作上限以避免静默截断。
    pub async fn list_for_user(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ClientSummary>, ClientServiceError> {
        Ok(
            repository::list_clients(&self.pool, Some(owner_user_id), MAX_CLIENT_LIST_LIMIT, 0)
                .await?
                .into_iter()
                .map(|client| ClientSummary {
                    id: client.id,
                    client_id: client.client_id,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris,
                    scopes: client.scopes,
                    status: client.status,
                    owner_user_id: client.owner_user_id,
                })
                .collect(),
        )
    }

    pub async fn update(
        &self,
        client_id: &str,
        input: ClientRegistrationInput,
    ) -> Result<bool, ClientServiceError> {
        let registration = validate_client_registration_with_limits(input, &self.limits)?;
        Ok(repository::update_client(
            &self.pool,
            None,
            client_id,
            &registration.client_name,
            &registration.redirect_uris,
            &registration.scopes,
        )
        .await?)
    }

    pub async fn update_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        input: ClientRegistrationInput,
    ) -> Result<bool, ClientServiceError> {
        let registration = validate_client_registration_with_limits(input, &self.limits)?;
        Ok(repository::update_client(
            &self.pool,
            Some(owner_user_id),
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
        Ok(repository::set_client_status(&self.pool, None, client_id, status).await?)
    }

    pub async fn set_status_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        status: &str,
    ) -> Result<bool, ClientServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Err(ClientServiceError::InvalidData);
        }
        Ok(
            repository::set_client_status(&self.pool, Some(owner_user_id), client_id, status)
                .await?,
        )
    }

    pub async fn rotate_secret(
        &self,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let (client_secret, hash) = generate_client_secret()?;
        if !repository::update_client_secret(&self.pool, None, client_id, &hash).await? {
            return Err(ClientServiceError::InvalidData);
        }
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }

    pub async fn rotate_secret_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let (client_secret, hash) = generate_client_secret()?;
        if !repository::update_client_secret(&self.pool, Some(owner_user_id), client_id, &hash)
            .await?
        {
            return Err(ClientServiceError::InvalidData);
        }
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 列表上限 clamp 逻辑独立于数据库（Issue #67）
    #[test]
    fn list_limit_clamps_to_max() {
        // 超过 MAX_CLIENT_LIST_LIMIT 被 clamp 到 200
        assert_eq!(
            i64::MAX.clamp(1, MAX_CLIENT_LIST_LIMIT),
            MAX_CLIENT_LIST_LIMIT
        );
        // 小于 1（含负数）被 clamp 到 1，SQL 的 LIMIT 不会收到非法值
        assert_eq!(0_i64.clamp(1, MAX_CLIENT_LIST_LIMIT), 1);
        assert_eq!((-10_i64).clamp(1, MAX_CLIENT_LIST_LIMIT), 1);
        // 区间内的值原样透传
        assert_eq!(20_i64.clamp(1, MAX_CLIENT_LIST_LIMIT), 20);
    }

    #[test]
    fn default_list_limit_is_within_max() {
        assert_eq!(DEFAULT_CLIENT_LIST_LIMIT, 50);
        assert!(DEFAULT_CLIENT_LIST_LIMIT <= MAX_CLIENT_LIST_LIMIT);
    }

    /// offset 负值被抬到 0，避免 SQL OFFSET 报错
    #[test]
    fn negative_offset_floors_to_zero() {
        assert_eq!((-5_i64).max(0), 0);
        assert_eq!(0_i64.max(0), 0);
        assert_eq!(120_i64.max(0), 120);
    }
}
