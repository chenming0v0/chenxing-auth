use serde::{Deserialize, Serialize};
use std::fmt;

use super::{AuthFactorService, AuthFactorServiceError, FactorVerification, TotpConfirmation};
use crate::{
    auth_factors::{
        crypto::{
            DecryptedTotpSecret, SecretCryptoError, decrypt_totp_secret_with_ring,
            encrypt_totp_secret_with_ring,
        },
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
        totp::{TotpEnrollment, verify_totp_code_now_timestep},
    },
    auth_limiter::{FailureDimension, LimiterDimension},
    users::domain::UserId,
};

const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";

#[derive(Clone, Serialize, Deserialize)]
struct PendingTotpSetup {
    user_id: UserId,
    encrypted_secret: Vec<u8>,
}

impl fmt::Debug for PendingTotpSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTotpSetup")
            .field("user_id", &self.user_id)
            .field("encrypted_secret", &"<redacted>")
            .finish()
    }
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

    pub async fn start_totp_enrollment(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        account_name: &str,
        issuer: &str,
    ) -> Result<Option<TotpEnrollment>, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(None);
        };
        let factor_methods = repository::list_factor_methods(&self.pool, ticket.user_id).await?;
        if !ticket.is_active_at(self.clock.now())
            || !ticket.supports(FactorMethod::Totp)
            || !self.can_start_totp_enrollment(&factor_methods).await?
        {
            return Ok(None);
        }
        let enrollment = TotpEnrollment::new(account_name, issuer)?;
        let encrypted_secret =
            encrypt_totp_secret_with_ring(&self.encryption_keys, enrollment.secret_bytes())?;
        // 一次原子写既做「是否已存在待确认注册」的检查，也做预留：胜者拿到 true，
        // 败者拿到 false 并原样返回 Ok(None)。这里不能退回先 find_json 再 save_json：
        // 两个并发 setup 请求会都读到空、都写入，后写的密钥覆盖先写的，而先请求的
        // 用户已经把前一个密钥存进了验证器 App，之后的确认码永远对不上（#265）。
        //
        // 败者丢弃自己刚生成的 enrollment：它从未离开进程，没有任何一方持有它，
        // 而已预留的密钥保持不变，胜者的确认流程不受影响。
        let reserved = self
            .tickets
            .save_json_if_absent(
                &Self::totp_setup_key(ticket_id),
                &PendingTotpSetup {
                    user_id: ticket.user_id,
                    encrypted_secret,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(reserved.then_some(enrollment))
    }

    pub async fn confirm_totp_enrollment(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Totp) {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        // 没有待确认的注册是一个独立事实，不能和「ticket 无效」共用一个变体：
        // 登录端点要靠它判断是否回落到 verify_totp_login，而回落之前一律不预留额度。
        let Some(pending) = self
            .tickets
            .find_json::<PendingTotpSetup>(&Self::totp_setup_key(ticket_id))
            .await?
        else {
            return Ok(TotpConfirmation::NoPendingEnrollment);
        };
        let factor_methods = repository::list_factor_methods(&self.pool, ticket.user_id).await?;
        let passkey_recovery = self.is_disabled_passkey_only(&factor_methods).await?;
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &pending.encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    // 待确认的注册密文是几分钟前用当时的 active key 写入的，
                    // 走到这里说明密钥环在注册过程中被换掉了。
                    //
                    // 只删掉这份读不出来的 pending 注册，**保留 ticket**：用户重新
                    // 调用 setup 就能拿到当前 active key 加密的新种子，无需重新输入
                    // 口令。连 ticket 一起废掉会把一个可自助恢复的场景升级成重新登录。
                    self.report_retired_key(dimensions, "enrollment").await;
                    self.tickets
                        .delete(&Self::totp_setup_key(ticket_id))
                        .await?;
                    return Ok(TotpConfirmation::KeyUnavailable);
                }
                Err(error) => {
                    self.release_dimensions_after_error(dimensions).await;
                    return Err(error.into());
                }
            };
        let valid = verify_totp_code_now_timestep(&decrypted.plaintext, code, self.clock.now());
        let Some(_) = valid else {
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
        // The setup ticket is one-time; only login verification claims a replay timestep.
        self.release_dimensions(dimensions).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = match consume_then_persist(
            TotpConfirmation::Completed(ticket.authenticated()),
            TotpConfirmation::InvalidTicket,
            self.tickets.take_for_holder(ticket_id, holder_hash),
            async {
                let result = if passkey_recovery {
                    repository::insert_totp_factor_for_passkey_recovery(
                        &self.pool,
                        ticket.user_id,
                        &pending.encrypted_secret,
                    )
                    .await?
                } else {
                    repository::insert_totp_factor_if_empty(
                        &self.pool,
                        ticket.user_id,
                        &pending.encrypted_secret,
                    )
                    .await?
                };
                match result {
                    repository::FirstFactorPersistenceResult::Stored => Ok(()),
                    repository::FirstFactorPersistenceResult::AlreadyExists => {
                        Err(AuthFactorServiceError::FirstFactorAlreadyExists)
                    }
                }
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await
        {
            Ok(confirmation) => confirmation,
            Err(AuthFactorServiceError::FirstFactorAlreadyExists) => {
                let _ = self.tickets.take_for_holder(ticket_id, holder_hash).await?;
                self.tickets
                    .delete(&Self::totp_setup_key(ticket_id))
                    .await?;
                return Ok(TotpConfirmation::InvalidTicket);
            }
            Err(error) => return Err(error),
        };
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(confirmation)
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

    async fn can_start_totp_enrollment(
        &self,
        methods: &[String],
    ) -> Result<bool, AuthFactorServiceError> {
        if methods.is_empty() {
            return Ok(true);
        }
        self.is_disabled_passkey_only(methods).await
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
    async fn report_retired_key(&self, dimensions: Vec<LimiterDimension>, stage: &'static str) {
        self.release_dimensions_for_key_unavailable(dimensions)
            .await;
        tracing::error!(
            event = "auth_factor.totp.decrypt_key_unavailable",
            stage,
            "TOTP secret is encrypted under a kid that is no longer in AUTH_ENCRYPTION_KEYS; \
             the factor cannot be verified and must be reset through the admin recovery endpoint"
        );
    }

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

    pub(super) fn totp_setup_key(ticket_id: &str) -> String {
        format!("{}{}", TOTP_SETUP_PREFIX, ticket_id)
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
