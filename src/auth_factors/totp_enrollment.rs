//! TOTP 首次注册的用例流程：种子预留、注册确认与失败补偿。
//!
//! 与 `totp_service` 分开的理由是生命周期不同，不是行数：注册处理的是「Redis 里
//! 一份还没落库的待确认种子」，登录处理的是「已经落库的因子」。两者只共用
//! `claim_totp_timestep` 这一个一次性验证码原语——共用它是刻意的（#301），
//! 一次性边界属于 user/timestep，不属于某条流程。

use serde::{Deserialize, Serialize};
use std::fmt;

use super::{AuthFactorService, AuthFactorServiceError, TotpConfirmation};
use crate::{
    auth_factors::{
        crypto::{SecretCryptoError, decrypt_totp_secret_with_ring, encrypt_totp_secret_with_ring},
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
        totp::{TotpEnrollment, verify_totp_code_current_timestep},
    },
    auth_limiter::FailureDimension,
    users::domain::UserId,
};

const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";

/// Redis 里待确认的注册。`user_id` 不是冗余信息：确认路径靠它验证载荷与 login
/// ticket 指向同一个用户（#301）。
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
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
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

    /// 确认待注册的 TOTP 因子，成功即完成一次登录。
    ///
    /// 操作顺序是这个函数的安全契约，不能重排（#301）：
    ///
    /// 1. 取 ticket → 取 pending → 校验 `pending.user_id == ticket.user_id`。
    ///    绑定检查在任何加密、限流和数据库写入之前，fail closed。
    /// 2. 预留失败额度 → 解密预留的种子 → 校验验证码。
    /// 3. **claim user/timestep**：与登录同一个原语，码在这一步变成已消费。
    /// 4. 消费 ticket（原子 take）。
    /// 5. 写入因子；失败则恢复 ticket。
    ///
    /// 失败语义（按发生位置）：
    ///
    /// - **pending user 不一致**：废 ticket 与 pending，`InvalidTicket`。
    /// - **kid 已退役**：只删 pending，保留 ticket，归还额度且不记账，
    ///   `KeyUnavailable`；用户重新 setup 即可，无需重新登录。
    /// - **验证码错误**：记一次失败，ticket 维度达阈值时废 ticket。
    /// - **claim 未命中**：码已在别处被消费，`InvalidCode`。ticket 与 pending
    ///   都保留，用户输下一个码即可。
    /// - **ticket 已被并发消费**：claim 已烧掉，`InvalidTicket`。这不制造错误因子，
    ///   因为 `consume_then_persist` 在没拿到 ticket 时根本不执行写入。
    /// - **写因子失败（瞬时故障）**：ticket 被恢复、pending 保留，claim **不归还**。
    ///   用户用同一张 ticket 输下一个码重试即可。不归还 claim 是刻意的：一旦
    ///   归还，攻击者就能靠制造写库失败把已用过的码退回可用状态，第 3 步的
    ///   边界等于白做。代价上限是等一个时间步，换来的是 replay 边界无洞。
    /// - **因子已存在（并发注册的败者）**：废 ticket 与 pending，`InvalidTicket`，
    ///   claim 保持烧毁——这个码确实被用于做了一次判断。
    ///
    /// 任何失败路径都不会留下「已写入但无法验证」的因子：写入是最后一步，且只在
    /// ticket 被原子消费之后执行。
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
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
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
        // pending 载荷自带 user_id，必须和 ticket 上的一致才继续（#301）。
        //
        // setup 键当前由 ticket_id 派生，两者天然同源，所以这条检查此刻不可能失败。
        // 正因为不可能失败，它才必须写出来：一旦键的派生方式改成按用户或按会话，
        // 缺了它就会把 A 预留的种子写成 B 的因子，而下面的 replay claim 还会打在
        // 错误的用户命名空间上——两个用户各自持有对方的一次性边界。
        //
        // fail closed 连 ticket 一起废掉，而不是只删 pending：载荷与 ticket 的绑定
        // 已经不可信，这张 ticket 上的任何后续判断都失去依据。代价是一次重新登录。
        if pending.user_id != ticket.user_id {
            tracing::error!(
                event = "auth_factor.totp.enrollment_user_mismatch",
                ticket_user_id = ticket.user_id,
                pending_user_id = pending.user_id,
                "pending TOTP enrollment is not bound to the login ticket user; \
                 discarding both the ticket and the pending enrollment"
            );
            self.invalidate_ticket(ticket_id, holder_hash).await?;
            return Ok(TotpConfirmation::InvalidTicket);
        }
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
        // 一次性验证码的边界属于 user/timestep，不属于某条流程（#301）。
        //
        // 注册和登录共用 `claim_totp_timestep` 这一个原语，才不会出现两套语义：
        // 旧实现只在登录侧 claim，于是刚用于注册确认的码在同一时间步内还能换一张
        // 新 login ticket 再用一次——ticket 是一次性的，验证码却不是。
        //
        // claim 必须在写因子之前：先写库再 claim 的话，两者之间的任何故障都会留下
        // 一个「因子已存在但码未消费」的窗口，正是要堵的那个窗口。
        //
        // claim 失败（码已被别处消费）返回 InvalidCode 而不是废 ticket：这是可恢复的
        // 冲突，pending 注册和 ticket 都保留，用户输下一个码即可。`claim_totp_timestep`
        // 已在成功与失败两条路径上处理完预留额度，这里不再重复归还。
        if !self
            .claim_totp_timestep(ticket.user_id, timestep, dimensions)
            .await?
        {
            return Ok(TotpConfirmation::InvalidCode);
        }
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

    async fn can_start_totp_enrollment(
        &self,
        methods: &[String],
    ) -> Result<bool, AuthFactorServiceError> {
        if methods.is_empty() {
            return Ok(true);
        }
        self.is_disabled_passkey_only(methods).await
    }

    pub(super) fn totp_setup_key(ticket_id: &str) -> String {
        format!("{TOTP_SETUP_PREFIX}{ticket_id}")
    }
}
