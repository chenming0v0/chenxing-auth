//! 因子恢复用例（#258 / #460）。
//!
//! 信封加密的 TOTP 种子带 `kid`。旧 key 从 `AUTH_ENCRYPTION_KEYS` 移除后，仍以它
//! 加密的密文永久不可读；而懒迁移挂在「一次成功验证之后」，验证本身已经失败，
//! 于是用户被彻底锁死。Passkey-only 账号丢了全部认证器时同样没有自助出口：
//! 登录要现有 Passkey，管理 Session 也要先登录，末位 Owner 会把自己锁死。
//! 本模块提供不依赖成功验证、也不依赖现有 Session/Passkey 的出口：
//!
//! - [`AuthFactorService::encryption_key_health`]：在移除旧 key **之前**就能看到
//!   还有多少密文引用环外的 kid，把 #258 从「事后救火」变成「事前可发现」。
//! - [`AuthFactorService::reset_totp_factor`]：丢弃不可读的密文，让账号回到
//!   「无因子」状态；密码登录仍可签发 Session，之后从安全设置重新注册。
//! - [`AuthFactorService::reset_passkey_factor`]：删除全部 Passkey 凭据并撤销
//!   会话，专治 Passkey-only 锁死（#460）。授权在 HTTP 层：Owner Session 或
//!   系统 `ADMIN_TOKEN`，后者是末位 Owner 的逃生通道。
//!
//! [`AuthFactorService::account_factor_status`] 是诊断入口：它回答
//! 「这个账号是被密钥退役锁死了，还是用户自己输错了码，还是只剩 Passkey」。
//!
//! 这些用例都不解密、不返回 kid、不返回种子、不返回 Passkey 凭据材料。

use super::{AuthFactorService, AuthFactorServiceError};
use crate::{
    auth_factors::{
        crypto::{SecretKeyState, classify_secret_key_state},
        repository,
    },
    sessions::store::revoke_all_for_user_in_transaction,
    users::{
        ManagementActorCredential,
        domain::{UserId, UserPermission},
        repository::management_actor::{
            lock_management_user_advisories, lock_management_user_rows,
            validate_locked_management_actor_permission,
        },
    },
};

/// 单次密钥健康度扫描的上限。管理端诊断端点不能变成全表扫描的放大器；
/// 超过上限时 [`EncryptionKeyHealth::truncated`] 为真，运维据此判断结论是否完整。
const KEY_HEALTH_SCAN_LIMIT: i64 = 10_000;

/// 某个账号的 TOTP 因子状态。不含种子、密文和 kid。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpFactorStatus {
    pub key_state: SecretKeyState,
    pub updated_at: time::OffsetDateTime,
}

/// 管理端查看的账号因子概览。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountFactorStatus {
    /// 已注册的因子方法名（去重后排序），例如 `["passkey", "totp"]`。
    pub methods: Vec<String>,
    /// 无 TOTP 注册时为 `None`。
    pub totp: Option<TotpFactorStatus>,
}

/// 密文相对当前密钥环的分布。`unavailable > 0` 表示已经有账号被锁死。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EncryptionKeyHealth {
    pub total: i64,
    pub scanned: i64,
    pub current: i64,
    pub rotatable: i64,
    pub legacy: i64,
    pub unavailable: i64,
    /// 密文总数超过扫描上限，统计只覆盖前 `scanned` 条。
    pub truncated: bool,
}

impl EncryptionKeyHealth {
    /// 把已分类的状态聚合成计数。与数据库无关，便于单独验证聚合语义。
    fn from_states(total: i64, states: impl IntoIterator<Item = SecretKeyState>) -> Self {
        let mut health = Self {
            total,
            ..Self::default()
        };
        for state in states {
            health.scanned += 1;
            match state {
                SecretKeyState::Current => health.current += 1,
                SecretKeyState::Rotatable => health.rotatable += 1,
                SecretKeyState::Legacy => health.legacy += 1,
                SecretKeyState::Unavailable => health.unavailable += 1,
            }
        }
        health.truncated = total > health.scanned;
        health
    }
}

/// Passkey 重置结果。`Missing` 与「删除成功」必须区分：管理端要能把
/// 「这个账号本来就没有 Passkey」如实回成 404，而不是伪装成一次成功的重置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyResetOutcome {
    /// 已删除。`removed` 是本次清掉的凭据条数，供审计核对。
    Removed { removed: i64 },
    /// 账号存在但没有 Passkey。
    Missing,
    /// 账号不存在。
    UnknownUser,
}

/// 重置结果。`Missing` 与「删除成功」必须区分：管理端要能把
/// 「这个账号本来就没有 TOTP」如实回成 404，而不是伪装成一次成功的重置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpResetOutcome {
    /// 已删除。`key_state` 是删除前密文的可读状态，用于审计区分
    /// 「救一个被锁死的账号」和「管理员主动移除一个健康的因子」。
    Removed { key_state: SecretKeyState },
    /// 账号存在但没有 TOTP 注册。
    Missing,
    /// 账号不存在。
    UnknownUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfServiceRemovalOutcome {
    Removed { removed: i64 },
    Missing,
    AuthenticationChanged,
}

impl AuthFactorService {
    pub async fn remove_own_totp_factor(
        &self,
        user_id: UserId,
        authenticated_epoch: i64,
    ) -> Result<SelfServiceRemovalOutcome, AuthFactorServiceError> {
        self.remove_own_factor(user_id, authenticated_epoch, true)
            .await
    }

    pub async fn remove_own_passkey_factor(
        &self,
        user_id: UserId,
        authenticated_epoch: i64,
    ) -> Result<SelfServiceRemovalOutcome, AuthFactorServiceError> {
        self.remove_own_factor(user_id, authenticated_epoch, false)
            .await
    }

    async fn remove_own_factor(
        &self,
        user_id: UserId,
        authenticated_epoch: i64,
        totp: bool,
    ) -> Result<SelfServiceRemovalOutcome, AuthFactorServiceError> {
        let mut transaction = self.pool.begin().await?;
        crate::settings::repository::lock_passkey_policy(&mut transaction).await?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, user_id).await?;
        let current_epoch: Option<i64> =
            crate::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if current_epoch != Some(authenticated_epoch) {
            transaction.rollback().await?;
            return Ok(SelfServiceRemovalOutcome::AuthenticationChanged);
        }
        if revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(SelfServiceRemovalOutcome::AuthenticationChanged);
        }
        let removed = if totp {
            i64::from(
                repository::delete_totp_factor_in_transaction(&mut transaction, user_id)
                    .await?
                    .is_some(),
            )
        } else {
            repository::delete_passkeys_in_transaction(&mut transaction, user_id).await?
        };
        if removed == 0 {
            transaction.rollback().await?;
            return Ok(SelfServiceRemovalOutcome::Missing);
        }
        transaction.commit().await?;
        if let Err(error) = self.clear_account_failures(user_id).await {
            tracing::error!(error = %error, "factor removed but failure counters were not cleared");
        }
        if totp && let Err(error) = self.tickets.clear_totp_replay(user_id).await {
            tracing::error!(error = %error, "TOTP removed but replay claims were not cleared");
        }
        Ok(SelfServiceRemovalOutcome::Removed { removed })
    }

    pub async fn account_factor_status(
        &self,
        user_id: UserId,
    ) -> Result<Option<AccountFactorStatus>, AuthFactorServiceError> {
        if repository::find_session_epoch(&self.pool, user_id)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let mut methods = repository::list_factor_methods(&self.pool, user_id).await?;
        // list_factor_methods 每个 passkey 凭据一行；管理视图只关心方法集合。
        methods.sort();
        methods.dedup();
        let totp = repository::find_totp_factor(&self.pool, user_id)
            .await?
            .map(|(ciphertext, updated_at)| TotpFactorStatus {
                key_state: classify_secret_key_state(&self.encryption_keys, &ciphertext),
                updated_at,
            });
        Ok(Some(AccountFactorStatus { methods, totp }))
    }

    /// 删除账号的 TOTP 因子并撤销该账号的全部活跃凭据，两步在同一事务内完成。
    ///
    /// 凭据是靠旧因子签发的，重置因子等于降级 MFA，留着旧凭据就把恢复通道变成了
    /// 后门；因此「撤销会话」与「删除因子」必须原子（Issue #331）。分两步各自提交
    /// 的话，撤销成功而删除失败会留下「会话已撤、因子未删」的中间态——用户被踢
    /// 下线而恢复动作没有完成，且没有补偿手段。同一事务内任一步失败即整体回滚：
    /// `Missing`/`UnknownUser` 分支不会留下任何副作用，操作可以安全重试。
    ///
    /// 实现顺序是先推进 `session_epoch` 撤销全部会话（Cookie 会话与已签发 Refresh
    /// Token 在同一水位上一起失效，Issue #409），再删除因子。因子不存在时整体回滚，
    /// epoch 推进与 outbox 事件全部撤销，账号的会话保持原样——不存在需要前置
    /// 只读检查的竞态窗口。advisory 锁与改密、会话签发、因子注册共用（#274），
    /// 本事务与它们严格串行，不存在"读到旧 epoch 又按旧水位放行"的中间态。
    ///
    /// 失败计数与一次性时间步 claim 的清理放在事务提交之后，是 best-effort：因子
    /// 已经删除，这个既成事实不能因为 Redis 暂时不可用而被改写成 500，否则调用方
    /// 会重复执行恢复动作。
    pub async fn reset_totp_factor(
        &self,
        user_id: UserId,
        credential: ManagementActorCredential,
    ) -> Result<TotpResetOutcome, AuthFactorServiceError> {
        let mut transaction = self.pool.begin().await?;
        crate::settings::repository::lock_passkey_policy(&mut transaction).await?;
        let lock_order =
            lock_management_user_advisories(&mut transaction, user_id, credential).await?;
        let locked = lock_management_user_rows(&mut transaction, &lock_order).await?;
        validate_locked_management_actor_permission(
            credential,
            &locked,
            UserPermission::ManageAuthFactors,
        )?;
        if locked.target.is_none() {
            // 账号在本次请求期间被删除（因子行随用户级联删除）：如实回
            // UnknownUser，撤销动作没有推进任何东西。
            transaction.rollback().await?;
            return Ok(TotpResetOutcome::UnknownUser);
        }
        if revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(TotpResetOutcome::UnknownUser);
        }
        let Some((ciphertext, _)) =
            repository::delete_totp_factor_in_transaction(&mut transaction, user_id).await?
        else {
            // 并发重置抢先删掉了同一份因子：整体回滚，撤销动作不留痕，
            // 用户不会被莫名踢下线（#331）。
            transaction.rollback().await?;
            return Ok(TotpResetOutcome::Missing);
        };
        let key_state = classify_secret_key_state(&self.encryption_keys, &ciphertext);
        transaction.commit().await?;
        if let Err(error) = self.clear_account_failures(user_id).await {
            tracing::error!(
                event = "auth_factor.totp.reset_limiter_not_cleared",
                error = %error,
                "TOTP factor was reset but its failure counters were not cleared"
            );
        }
        // 一次性时间步 claim 也一起清掉：旧 claim 保护的是已删除因子的验证码，
        // 留着只会挡住同一时间步窗口内的重新注册（#301 之后注册确认也 claim）。
        // 与失败计数一样放在提交后 best-effort——因子删除已是既成事实。
        if let Err(error) = self.tickets.clear_totp_replay(user_id).await {
            tracing::error!(
                event = "auth_factor.totp.reset_replay_claims_not_cleared",
                error = %error,
                "TOTP factor was reset but its replay claims were not cleared"
            );
        }
        Ok(TotpResetOutcome::Removed { key_state })
    }

    /// 删除账号的全部 Passkey 凭据并撤销该账号的全部活跃凭据，两步在同一事务内完成。
    ///
    /// Passkey-only 账号丢了认证器之后，自助路径是闭环：登录要现有 Passkey，
    /// 管理 Session 要先登录。本用例本身不查 Session、不验 Passkey，只改持久化
    /// 事实；谁能调用由 HTTP 层用 Owner 的 `ManageAuthFactors` 或系统
    /// `ADMIN_TOKEN` 决定。后者不依赖任何用户 Session，是末位 Owner 的逃生口
    /// （Issue #460）。
    ///
    /// 凭据是靠旧 Passkey 签发的，重置等于拆掉第二因子，留着旧凭据就把恢复
    /// 通道变成后门。因此「撤销会话」与「删除凭据」必须原子，顺序与
    /// [`Self::reset_totp_factor`] 相同：先推进 `session_epoch`（Cookie 会话与
    /// 已签发 Refresh Token 在同一水位上一起失效，Issue #409），再删除全部
    /// Passkey。没有凭据可删时整体回滚，epoch 推进与 outbox 事件全部撤销。
    /// advisory 锁与改密、会话签发、因子注册共用（#274），本事务与它们严格
    /// 串行。
    ///
    /// 失败计数清理放在事务提交之后，是 best-effort：凭据已经删除，这个既成
    /// 事实不能因为 Redis 暂时不可用而被改写成 500。
    pub async fn reset_passkey_factor(
        &self,
        user_id: UserId,
        credential: ManagementActorCredential,
    ) -> Result<PasskeyResetOutcome, AuthFactorServiceError> {
        let mut transaction = self.pool.begin().await?;
        crate::settings::repository::lock_passkey_policy(&mut transaction).await?;
        let lock_order =
            lock_management_user_advisories(&mut transaction, user_id, credential).await?;
        let locked = lock_management_user_rows(&mut transaction, &lock_order).await?;
        validate_locked_management_actor_permission(
            credential,
            &locked,
            UserPermission::ManageAuthFactors,
        )?;
        if locked.target.is_none() {
            transaction.rollback().await?;
            return Ok(PasskeyResetOutcome::UnknownUser);
        }
        if revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(PasskeyResetOutcome::UnknownUser);
        }
        let removed = repository::delete_passkeys_in_transaction(&mut transaction, user_id).await?;
        if removed == 0 {
            // 并发重置抢先删掉了全部凭据：整体回滚，撤销动作不留痕。
            transaction.rollback().await?;
            return Ok(PasskeyResetOutcome::Missing);
        }
        transaction.commit().await?;
        if let Err(error) = self.clear_account_failures(user_id).await {
            tracing::error!(
                event = "auth_factor.passkey.reset_limiter_not_cleared",
                error = %error,
                "Passkey factor was reset but its failure counters were not cleared"
            );
        }
        Ok(PasskeyResetOutcome::Removed { removed })
    }

    /// 统计 TOTP 密文相对当前密钥环的可读状态分布。
    ///
    /// 移除 `AUTH_ENCRYPTION_KEYS` 中的旧 key 之前应当先看这个：`unavailable` 非零
    /// 说明已经有账号读不出种子，`rotatable` 非零说明还有账号依赖非 active key，
    /// 此刻退役该 key 就会制造新的锁死账号。
    pub async fn encryption_key_health(
        &self,
    ) -> Result<EncryptionKeyHealth, AuthFactorServiceError> {
        let total = repository::count_totp_factors(&self.pool).await?;
        let rows = repository::list_totp_ciphertexts(&self.pool, KEY_HEALTH_SCAN_LIMIT).await?;
        let states = rows
            .iter()
            .map(|(_, ciphertext)| classify_secret_key_state(&self.encryption_keys, ciphertext));
        let health = EncryptionKeyHealth::from_states(total, states);
        if health.unavailable > 0 {
            tracing::error!(
                event = "auth_factor.encryption_key_health.unreadable_secrets",
                unavailable = health.unavailable,
                scanned = health.scanned,
                "TOTP secrets are encrypted under kids that are no longer configured; \
                 those accounts cannot authenticate until their factor is reset"
            );
        }
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptionKeyHealth, PasskeyResetOutcome, TotpResetOutcome};
    use crate::auth_factors::crypto::SecretKeyState;

    #[test]
    fn key_health_counts_each_state_separately() {
        let health = EncryptionKeyHealth::from_states(
            4,
            [
                SecretKeyState::Current,
                SecretKeyState::Rotatable,
                SecretKeyState::Legacy,
                SecretKeyState::Unavailable,
            ],
        );

        assert_eq!(health.scanned, 4);
        assert_eq!(health.current, 1);
        assert_eq!(health.rotatable, 1);
        assert_eq!(health.legacy, 1);
        assert_eq!(health.unavailable, 1);
        assert!(!health.truncated);
    }

    #[test]
    fn key_health_reports_truncation_when_the_scan_does_not_cover_everything() {
        // 结论不完整时必须自报，否则运维会把「扫到的 0 个不可读」当成
        // 「全库没有不可读」，从而放心退役一个仍被引用的 key。
        let health = EncryptionKeyHealth::from_states(50_000, [SecretKeyState::Current]);

        assert_eq!(health.total, 50_000);
        assert_eq!(health.scanned, 1);
        assert!(health.truncated);
    }

    #[test]
    fn empty_scan_is_not_reported_as_truncated() {
        let health = EncryptionKeyHealth::from_states(0, Vec::<SecretKeyState>::new());
        assert_eq!(health.scanned, 0);
        assert!(!health.truncated);
    }

    #[test]
    fn reset_outcome_distinguishes_missing_factor_from_missing_user() {
        // 两种 404 的语义不同，管理端要能如实区分，不能合并成一个「失败」。
        assert_ne!(TotpResetOutcome::Missing, TotpResetOutcome::UnknownUser);
        assert_ne!(
            TotpResetOutcome::Removed {
                key_state: SecretKeyState::Unavailable
            },
            TotpResetOutcome::Removed {
                key_state: SecretKeyState::Current
            }
        );
    }

    #[test]
    fn passkey_reset_outcome_distinguishes_missing_factor_from_missing_user() {
        assert_ne!(
            PasskeyResetOutcome::Missing,
            PasskeyResetOutcome::UnknownUser
        );
        assert_ne!(
            PasskeyResetOutcome::Removed { removed: 1 },
            PasskeyResetOutcome::Removed { removed: 2 }
        );
        assert_ne!(
            PasskeyResetOutcome::Removed { removed: 0 },
            PasskeyResetOutcome::Missing
        );
    }
}
