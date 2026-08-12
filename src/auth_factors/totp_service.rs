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
        totp::verify_totp_code_current_timestep,
    },
    auth_limiter::{FailureDimension, LimiterDimension},
    users::domain::UserId,
};

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
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
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
        let timestep = verify_totp_code_current_timestep(&decrypted.plaintext, code);
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
        if let Err(error) = self
            .reencrypt_totp_secret_if_needed(user_id, &encrypted_secret, &decrypted)
            .await
        {
            tracing::warn!(
                event = "auth_factor.totp.lazy_reencryption_failed",
                error = %error,
                "TOTP verification succeeded but key rotation migration was deferred"
            );
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
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
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
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id, holder_hash).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
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
        let valid = verify_totp_code_current_timestep(&decrypted.plaintext, code);
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
        if let Err(error) = self
            .reencrypt_totp_secret_if_needed(ticket.user_id, &encrypted_secret, &decrypted)
            .await
        {
            tracing::warn!(
                event = "auth_factor.totp.lazy_reencryption_failed",
                error = %error,
                "TOTP verification succeeded but key rotation migration was deferred"
            );
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

    pub(super) async fn reencrypt_totp_secret_if_needed(
        &self,
        user_id: UserId,
        current_ciphertext: &[u8],
        decrypted: &DecryptedTotpSecret,
    ) -> Result<(), AuthFactorServiceError> {
        if !decrypted.needs_reencryption {
            return Ok(());
        }
        let replacement =
            encrypt_totp_secret_with_ring(&self.encryption_keys, &decrypted.plaintext)?;
        repository::update_totp_factor_if_current(
            &self.pool,
            user_id,
            current_ciphertext,
            &replacement,
        )
        .await?;
        Ok(())
    }
}
