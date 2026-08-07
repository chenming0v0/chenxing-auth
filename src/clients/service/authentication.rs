//! Client credential authentication.

use super::{ClientService, ClientServiceError};
use crate::clients::{
    credentials::verify_client_credentials_constant_time,
    domain::ClientAuthMethod,
    repository,
};

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
        // 唯一的 `?` 早退是数据库错误，它与 client 是否存在无关，不构成侧信道。
        let stored = repository::find_client_credentials(&self.pool, client_id).await?;
        Ok(
            verify_client_credentials_constant_time(auth_method, client_secret, stored.as_ref())
                .await,
        )
    }
}
