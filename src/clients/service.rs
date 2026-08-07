use crate::sqlx::PgPool;
use crate::users::domain::UserId;
use serde::Serialize;
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

use super::{
    credentials::{
        generate_client_secret, issue_client_credential, prepare_dummy_client_secret_hash,
        verify_client_credentials_constant_time,
    },
    domain::{
        ClientAuthMethod, ClientRegistrationError, ClientRegistrationInput,
        ClientRegistrationLimits, validate_client_registration_with_limits,
    },
    repository::{self, ClientInsertError},
};
use crate::oauth::authorization::RegisteredClient as OAuthRegisteredClient;
use crate::oauth::refresh_store::RefreshTokenStore;

// 凭据签发/校验拆到 credentials.rs（src-line-limit），此处保持既有公开路径不变。
pub use super::credentials::{ClientRegistrationRequest, verify_client_secret};

/// 管理端 Client 列表的默认与最大返回条数，与 User 列表保持一致。
const DEFAULT_CLIENT_LIST_LIMIT: i64 = 50;
const MAX_CLIENT_LIST_LIMIT: i64 = 200;

// 默认值必须落在上限内，否则 `normalize_list_limit` 的缺省分支会被 clamp 静默改写。
// 这是常量间的不变量，放在编译期断言里，改坏常量会直接编译失败。
const _: () = assert!(DEFAULT_CLIENT_LIST_LIMIT <= MAX_CLIENT_LIST_LIMIT);

/// 缺省取 `DEFAULT_CLIENT_LIST_LIMIT`，并夹到 `[1, MAX_CLIENT_LIST_LIMIT]`，
/// 避免非法值直接进入 SQL 的 LIMIT。
fn normalize_list_limit(limit: Option<i64>) -> i64 {
    limit
        .unwrap_or(DEFAULT_CLIENT_LIST_LIMIT)
        .clamp(1, MAX_CLIENT_LIST_LIMIT)
}

/// 缺省与负值都抬到 0，避免 SQL 的 OFFSET 收到负数报错。
fn normalize_list_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).max(0)
}

#[derive(Clone)]
pub struct ClientService {
    pool: PgPool,
    limits: ClientRegistrationLimits,
    /// Refresh Token 存储，用于 Secret 轮换时撤销已签发的凭据（Issue #62）。
    ///
    /// 用 `Option` 是为了让不依赖 Redis 的单元测试仍能构造 `ClientService`；
    /// 生产路径由 `AppState::new` 通过 `with_refresh_tokens` 注入。
    /// 为 `None` 时轮换会记 `tracing::error!`，避免静默退化成安全空操作。
    refresh_tokens: Option<RefreshTokenStore>,
}

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

impl fmt::Debug for RegisteredClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredClientSecret")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("client_name", &self.client_name)
            .field("redirect_uris", &self.redirect_uris)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .finish()
    }
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

#[derive(Serialize)]
pub struct RotatedClientSecret {
    pub client_id: String,
    pub client_secret: String,
}

impl fmt::Debug for RotatedClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatedClientSecret")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
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
        // 在服务开始接受请求前准备计时填充，避免首个失败认证多执行一次
        // dummy 哈希生成；请求期的校验仍全部在 spawn_blocking 中运行。
        prepare_dummy_client_secret_hash();
        Self {
            pool,
            limits,
            refresh_tokens: None,
        }
    }

    /// 注入 Refresh Token 存储（Issue #62：Secret 轮换需要撤销已签发的 token）。
    ///
    /// 建造者模式，返回 `Self` 支持链式调用。生产路径由 `AppState` 构造时注入。
    pub fn with_refresh_tokens(mut self, store: RefreshTokenStore) -> Self {
        self.refresh_tokens = Some(store);
        self
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

    /// 校验 Client 凭据（Issue #63：消除计时侧信道）。
    ///
    /// 本函数刻意**没有任何早退**。旧实现在「client_id 不存在」时只做一次
    /// DB 查询就 `return Ok(false)`，而「client_id 存在但 secret 错」会额外
    /// 执行一次毫秒级的 Argon2 计算。两条路径的耗时差远大于 DB 查询抖动，
    /// 攻击者可以用响应时间批量枚举出平台上有效的 client_id（令牌端点的
    /// 30 QPS 限流不足以阻止枚举）。status / auth_method 的早退同理。
    ///
    /// 因此这里把「查库 → 廉价策略比较 → 一次 Argon2 → 统一判定」固定成
    /// 单一直线路径：无论 client 是否存在、status 与 auth_method 是否合法，
    /// 都对某个真实的 Argon2 哈希执行且仅执行一次校验（失败路径用 dummy 哈希），
    /// 使所有失败原因在时序上不可区分。
    pub async fn verify_credentials(
        &self,
        client_id: &str,
        auth_method: ClientAuthMethod,
        client_secret: Option<&str>,
    ) -> Result<bool, ClientServiceError> {
        // 唯一的 `?` 早退是数据库错误，它与 client 是否存在无关，不构成侧信道。
        let stored = repository::find_client_credentials(&self.pool, client_id).await?;
        Ok(
            verify_client_credentials_constant_time(auth_method, client_secret, stored.as_ref())
                .await,
        )
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
        let limit = normalize_list_limit(limit);
        let offset = normalize_list_offset(offset);
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
        self.revoke_refresh_tokens_after_rotation(client_id).await;
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
        self.revoke_refresh_tokens_after_rotation(client_id).await;
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }

    /// Secret 轮换后撤销该 Client 的全部 Refresh Token（Issue #62）。
    ///
    /// 不这么做的话「轮换」是安全空操作：攻击者拿到泄露的 Secret 换出的
    /// Refresh Token 在轮换后依然能继续换取新 Access Token，
    /// 管理员以为已经止损，实际没有。
    ///
    /// **故意不回滚 secret**（设计决策 §4）：新 secret 已经写入数据库并生效，
    /// 回滚会让「轮换没生效」这个更危险的状态被静默掩盖。撤销失败留下的
    /// 「旧 token 仍可用」是降级状态，通过 `tracing::error!` 暴露给运维，
    /// 可人工再次轮换或直接停用 Client。
    ///
    /// 同理，撤销失败不改变函数返回值：调用方必须拿到新 secret，
    /// 否则该 Client 会因为「新 secret 已生效但调用者不知道」而完全无法认证。
    async fn revoke_refresh_tokens_after_rotation(&self, client_id: &str) {
        let Some(store) = self.refresh_tokens.as_ref() else {
            // 未注入存储属于装配错误（生产路径一定会注入）。
            // 记 error 而不是静默跳过，否则 #62 会悄悄回归。
            tracing::error!(
                client_id = %client_id,
                "client secret rotated without refresh token store; \
                 previously issued refresh tokens remain valid (Issue #62)"
            );
            return;
        };
        match store.revoke_client_tokens(client_id).await {
            Ok(revoked) => {
                tracing::info!(
                    client_id = %client_id,
                    revoked_refresh_tokens = revoked,
                    "revoked refresh tokens after client secret rotation"
                );
            }
            Err(store_error) => {
                tracing::error!(
                    error = %store_error,
                    client_id = %client_id,
                    "failed to revoke refresh tokens after client secret rotation; \
                     previously issued tokens may still be usable (Issue #62)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 列表上限 clamp 逻辑独立于数据库（Issue #67）
    #[test]
    fn list_limit_clamps_to_max() {
        // 超过 MAX_CLIENT_LIST_LIMIT 被 clamp 到 200
        assert_eq!(normalize_list_limit(Some(i64::MAX)), MAX_CLIENT_LIST_LIMIT);
        // 小于 1（含负数）被 clamp 到 1，SQL 的 LIMIT 不会收到非法值
        assert_eq!(normalize_list_limit(Some(0)), 1);
        assert_eq!(normalize_list_limit(Some(-10)), 1);
        // 区间内的值原样透传
        assert_eq!(normalize_list_limit(Some(20)), 20);
    }

    #[test]
    fn default_list_limit_is_within_max() {
        assert_eq!(DEFAULT_CLIENT_LIST_LIMIT, 50);
        // 默认值与上限的关系由文件顶部的编译期断言保证，这里只验证缺省分支的取值。
        assert_eq!(normalize_list_limit(None), DEFAULT_CLIENT_LIST_LIMIT);
    }

    /// offset 负值被抬到 0，避免 SQL OFFSET 报错
    #[test]
    fn negative_offset_floors_to_zero() {
        assert_eq!(normalize_list_offset(Some(-5)), 0);
        assert_eq!(normalize_list_offset(Some(0)), 0);
        assert_eq!(normalize_list_offset(Some(120)), 120);
        // 不传 offset 时从头开始
        assert_eq!(normalize_list_offset(None), 0);
    }
}
