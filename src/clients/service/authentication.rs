//! Client credential authentication and issuance fencing.

use super::{AuthenticatedClient, ClientService, ClientServiceError};
use crate::clients::{
    credentials::verify_client_credentials_constant_time, domain::ClientAuthMethod, repository,
};

/// A PostgreSQL row lock that fences one Refresh Token persistence operation
/// against Client Secret rotation across all application instances.
pub(crate) struct ClientCredentialIssuanceGuard {
    transaction: crate::sqlx::Transaction<'static, crate::sqlx::Postgres>,
}

impl ClientCredentialIssuanceGuard {
    /// The transaction is read-only; rollback is the cheapest explicit way to
    /// release its row lock without pretending there is state to commit.
    pub(crate) async fn release(self) -> Result<(), crate::sqlx::Error> {
        self.transaction.rollback().await
    }
}

impl ClientService {
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
        Ok(self
            .authenticate_credentials(client_id, auth_method, client_secret)
            .await?
            .is_some())
    }

    /// Authenticate and retain the version of the exact hash that succeeded.
    pub async fn authenticate_credentials(
        &self,
        client_id: &str,
        auth_method: ClientAuthMethod,
        client_secret: Option<&str>,
    ) -> Result<Option<AuthenticatedClient>, ClientServiceError> {
        // 唯一的 `?` 早退是数据库错误，它与 client 是否存在无关，不构成侧信道。
        let stored = repository::find_client_credentials(&self.pool, client_id).await?;
        let valid =
            verify_client_credentials_constant_time(auth_method, client_secret, stored.as_ref())
                .await;
        Ok(match (valid, stored) {
            (true, Some(stored)) => Some(AuthenticatedClient::new(
                client_id.to_owned(),
                stored.client_secret_version,
                stored.allow_legacy_refresh_tokens,
            )),
            _ => None,
        })
    }

    /// Acquire the multi-instance persistence fence for an authenticated
    /// credential snapshot.
    pub(crate) async fn acquire_issuance_guard(
        &self,
        authenticated: &AuthenticatedClient,
    ) -> Result<Option<ClientCredentialIssuanceGuard>, ClientServiceError> {
        let mut transaction = self.pool.begin().await?;
        if !repository::lock_client_credentials_if_version(
            &mut transaction,
            authenticated.client_id(),
            authenticated.client_secret_version(),
            authenticated.allows_legacy_refresh_tokens(),
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        Ok(Some(ClientCredentialIssuanceGuard { transaction }))
    }
}
