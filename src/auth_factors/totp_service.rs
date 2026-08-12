//! 已注册 TOTP 因子的验证：内联登录、ticket 登录，以及两者共用的
//! 一次性验证码 claim、ticket 失效与惰性重加密。
//!
//! 首次注册的种子预留与确认在 `totp_enrollment`。

use super::{AuthFactorService, AuthFactorServiceError, FactorVerification, TotpConfirmation};
use crate::{
    auth_factors::{
        crypto::{
            DecryptedTotpSecret, SecretCryptoError, decrypt_totp_secret_with_ring,
            encrypt_totp_secret_with_ring,
        },
        domain::FactorMethod,
        repository,
        totp::verify_totp_code_now_timestep,
    },
    auth_limiter::{FailureDimension, LimiterDimension},
    users::domain::UserId,
};

/// 惰性重加密的处置结果（#360）。
///
/// 调用方必须区分 `Missing`：CAS 失败且因子行已不存在时，验证只对
/// 「读取时刻的那份密文」成立，该密文已不再对应任何现存因子，不能按
/// 「因子仍然存在」继续完成认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TotpReencryptionOutcome {
    /// 密文已用当前密钥加密，无需迁移。
    NotNeeded,
    /// 本次 CAS 写入成功，已替换为当前密钥的密文。
    Reencrypted,
    /// 并发请求已完成同一种子的重加密：本次无事可做，验证依然有效。
    Superseded,
    /// 因子已被并发重置/删除：验证结果对现存账号状态不再成立。
    Missing,
}

impl AuthFactorService {
    pub async fn verify_totp(
        &self,
        user_id: UserId,
        _identifier: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<FactorVerification, AuthFactorServiceError> {
        let account_key = self.account_key(user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, None, source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Err(AuthFactorServiceError::RateLimited);
        }
        let encrypted_secret = match repository::find_totp_secret(&self.pool, user_id).await {
            Ok(encrypted_secret) => encrypted_secret,
            Err(error) => {
                // 已确定返回错误：归还失败只记日志，不覆盖真实故障原因。
                self.release_dimensions_after_error(dimensions).await;
                return Err(error.into());
            }
        };
        let Some(encrypted_secret) = encrypted_secret else {
            // 因子不存在 ≠ 用户失败（#340）：调用方刚从 `available_methods` 看到
            // 因子，这里却读不到，是管理员重置/删除与读取之间的竞态，或客户端仍
            // 按旧状态提交验证码。没有因子就没有可校验的密钥，重试永远失败，
            // 不存在可爆破的目标；记入账号维度会烧掉与密码失败共享的额度，把
            // 受害者从「TOTP 不可用」推进到「连密码登录都被限流」。
            self.release_dimensions_for_missing_factor(dimensions).await;
            return Ok(FactorVerification::Rejected);
        };
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    self.report_retired_key(dimensions, "verify").await;
                    return Ok(FactorVerification::KeyUnavailable);
                }
                Err(error) => {
                    self.release_dimensions_after_error(dimensions).await;
                    return Err(error.into());
                }
            };
        // 直接借用 decrypted.plaintext：它是 Zeroizing<Vec<u8>>，drop 时自动清零。
        // 旧写法 clone + fill(0) 只擦除了克隆副本，原始明文缓冲区反而活得更久
        // （后面还要传给 reencrypt_totp_secret_if_needed），等于没有真正擦除。
        let timestep = verify_totp_code_now_timestep(&decrypted.plaintext, code, self.clock.now());
        let Some(timestep) = timestep else {
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
            return Ok(FactorVerification::Rejected);
        };
        if !self
            .claim_totp_timestep(user_id, timestep, dimensions)
            .await?
        {
            return Ok(FactorVerification::Rejected);
        }
        match self
            .reencrypt_totp_secret_if_needed(user_id, &encrypted_secret, &decrypted)
            .await
        {
            // 因子已被并发重置/删除：码虽然对「读取时的那份密文」成立，但该
            // 因子已不存在。按「因子不存在」拒绝，且不记失败——码本身是对的，
            // 额度已在 claim 时归还（#360）。
            Ok(TotpReencryptionOutcome::Missing) => return Ok(FactorVerification::Rejected),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    event = "auth_factor.totp.lazy_reencryption_failed",
                    error = %error,
                    "TOTP verification succeeded but key rotation migration was deferred"
                );
            }
        }
        Ok(FactorVerification::Accepted)
    }

    pub async fn verify_totp_login(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        // ticket 的签发时刻由 store 用同一个时钟盖下（store.rs），有效期判定
        // 必须同源，否则固定时钟下「刚签发的 ticket 已过期」会成为真实矛盾。
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Totp) {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let encrypted_secret = match repository::find_totp_secret(&self.pool, ticket.user_id).await
        {
            Ok(encrypted_secret) => encrypted_secret,
            Err(error) => {
                self.release_dimensions_after_error(dimensions).await;
                return Err(error.into());
            }
        };
        let Some(encrypted_secret) = encrypted_secret else {
            // 「读不到因子」与并发删除（Missing）同一语义（#360）：InvalidTicket，
            // 且不记失败（#340）。因子不存在就不是用户输错码，记账只会烧掉与密码
            // 失败共享的账号额度；ticket 也不在此作废——它可能还支持其他因子
            // （如 passkey），留到 TTL 自然过期即可。
            self.release_dimensions_for_missing_factor(dimensions).await;
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    self.report_retired_key(dimensions, "login").await;
                    return Ok(TotpConfirmation::KeyUnavailable);
                }
                Err(error) => {
                    self.release_dimensions_after_error(dimensions).await;
                    return Err(error.into());
                }
            };
        let valid = verify_totp_code_now_timestep(&decrypted.plaintext, code, self.clock.now());
        let Some(timestep) = valid else {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id, holder_hash).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        };
        if !self
            .claim_totp_timestep(ticket.user_id, timestep, dimensions)
            .await?
        {
            return Ok(TotpConfirmation::InvalidCode);
        }
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        match self
            .reencrypt_totp_secret_if_needed(ticket.user_id, &encrypted_secret, &decrypted)
            .await
        {
            // 因子已被并发重置/删除：与「读不到因子」同一语义（InvalidTicket），
            // 但不记失败——码本身是对的，额度已在 claim 时归还（#360）。
            Ok(TotpReencryptionOutcome::Missing) => return Ok(TotpConfirmation::InvalidTicket),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    event = "auth_factor.totp.lazy_reencryption_failed",
                    error = %error,
                    "TOTP verification succeeded but key rotation migration was deferred"
                );
            }
        }
        if self
            .tickets
            .take_for_holder(ticket_id, holder_hash)
            .await?
            .is_none()
        {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        Ok(TotpConfirmation::Completed(ticket.authenticated()))
    }

    /// kid 已退役时的统一处置：归还预留额度并告警。
    ///
    /// 三条不变量：
    /// 1. **不烧失败额度**。这不是用户的失败尝试，把它计入账户/IP 计数会让一个
    ///    运维动作把用户从「TOTP 不可用」升级为「连密码登录都被限流」。
    /// 2. 归还走 best-effort 路径。结果已经确定为 `KeyUnavailable`，让限流后端故障
    ///    把它改写成 500 只会掩盖真正的原因。
    /// 3. `error!` 而非 `warn!`：这是配置错误导致的账号锁死，需要人工介入，
    ///    必须能被告警规则捕获。日志不含 kid、邮箱和种子。
    pub(super) async fn report_retired_key(
        &self,
        dimensions: Vec<LimiterDimension>,
        stage: &'static str,
    ) {
        self.release_dimensions_for_key_unavailable(dimensions)
            .await;
        tracing::error!(
            event = "auth_factor.totp.decrypt_key_unavailable",
            stage,
            "TOTP secret is encrypted under a kid that is no longer in AUTH_ENCRYPTION_KEYS; \
             the factor cannot be verified and must be reset through the admin recovery endpoint"
        );
    }

    /// 一次性验证码的唯一消费点，注册确认与登录验证共用（#301）。
    ///
    /// 边界的粒度是 `user + timestep`，与调用它的是哪条流程无关：谁先 claim 到，
    /// 这个码就归谁；晚到的一方拿到 `false`，无论它来自注册还是登录。
    ///
    /// 无论 claim 命中与否，本函数都负责归还预留的失败额度——claim 未命中不是
    /// 用户输错了码，不该计入失败计数。调用方只需要处理返回值。
    pub(super) async fn claim_totp_timestep(
        &self,
        user_id: UserId,
        timestep: u64,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, AuthFactorServiceError> {
        let claimed = match self.tickets.claim_totp_timestep(user_id, timestep).await {
            Ok(claimed) => claimed,
            Err(error) => {
                self.release_dimensions_after_error(dimensions).await;
                return Err(error.into());
            }
        };
        self.release_dimensions(dimensions).await?;
        Ok(claimed)
    }

    pub(super) async fn invalidate_ticket(
        &self,
        ticket_id: &str,
        holder_hash: &str,
    ) -> Result<(), AuthFactorServiceError> {
        self.tickets.take_for_holder(ticket_id, holder_hash).await?;
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(())
    }

    /// 惰性重加密：仅在密文使用非当前密钥时用当前密钥环重加密并 CAS 写入。
    pub(super) async fn reencrypt_totp_secret_if_needed(
        &self,
        user_id: UserId,
        current_ciphertext: &[u8],
        decrypted: &DecryptedTotpSecret,
    ) -> Result<TotpReencryptionOutcome, AuthFactorServiceError> {
        if !decrypted.needs_reencryption {
            return Ok(TotpReencryptionOutcome::NotNeeded);
        }
        let replacement =
            encrypt_totp_secret_with_ring(&self.encryption_keys, &decrypted.plaintext)?;
        let outcome = repository::update_totp_factor_if_current(
            &self.pool,
            user_id,
            current_ciphertext,
            &replacement,
        )
        .await?;
        Ok(match outcome {
            repository::TotpCasUpdateOutcome::Updated => TotpReencryptionOutcome::Reencrypted,
            repository::TotpCasUpdateOutcome::Superseded => TotpReencryptionOutcome::Superseded,
            repository::TotpCasUpdateOutcome::Missing => TotpReencryptionOutcome::Missing,
        })
    }
}
