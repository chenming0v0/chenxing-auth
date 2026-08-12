//! 因子恢复用例（#258）。
//!
//! 信封加密的 TOTP 种子带 `kid`。旧 key 从 `AUTH_ENCRYPTION_KEYS` 移除后，仍以它
//! 加密的密文永久不可读；而懒迁移挂在「一次成功验证之后」，验证本身已经失败，
//! 于是用户被彻底锁死。本模块提供两条不依赖成功验证的出口：
//!
//! - [`AuthFactorService::encryption_key_health`]：在移除旧 key **之前**就能看到
//!   还有多少密文引用环外的 kid，把 #258 从「事后救火」变成「事前可发现」。
//! - [`AuthFactorService::reset_totp_factor`]：丢弃不可读的密文，让账号回到
//!   「无因子」状态，下次密码登录走 `factor_setup_required` 重新注册。
//!
//! [`AuthFactorService::account_factor_status`] 是这两者的诊断入口：它回答
//! 「这个账号是被密钥退役锁死了，还是用户自己输错了码」。
//!
//! 三者都不解密、不返回 kid、不返回种子。

use super::{AuthFactorService, AuthFactorServiceError};
use crate::{
    auth_factors::{
        crypto::{SecretKeyState, classify_secret_key_state},
        repository,
    },
    users::domain::UserId,
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

impl AuthFactorService {
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

    /// 删除账号的 TOTP 因子，并清掉它累积的失败计数。
    ///
    /// 不清理失败计数的话，被锁死期间攒下的账户维度计数会在重置后继续挡住
    /// 新一轮登录——用户看到的仍然是「被限流」，等于恢复动作只做了一半。
    ///
    /// 调用方（管理 handler）负责在删除**之前**撤销该账号的活跃凭据：Cookie
    /// 会话与已签发 Refresh Token 由 `session_epoch` 推进统一失效（Issue #409）。
    /// 凭据是靠旧因子签发的，重置因子等于降级 MFA，留着旧凭据就把恢复通道
    /// 变成了后门。
    pub async fn reset_totp_factor(
        &self,
        user_id: UserId,
    ) -> Result<TotpResetOutcome, AuthFactorServiceError> {
        if repository::find_session_epoch(&self.pool, user_id)
            .await?
            .is_none()
        {
            return Ok(TotpResetOutcome::UnknownUser);
        }
        let Some((ciphertext, _)) = repository::find_totp_factor(&self.pool, user_id).await? else {
            return Ok(TotpResetOutcome::Missing);
        };
        let key_state = classify_secret_key_state(&self.encryption_keys, &ciphertext);
        if !repository::delete_totp_factor(&self.pool, user_id).await? {
            // 并发重置：另一个请求已经删掉了同一份因子。
            return Ok(TotpResetOutcome::Missing);
        }
        // 失败计数清理是 best-effort：因子已经删除，这个既成事实不能因为
        // Redis 暂时不可用而被改写成 500，否则调用方会重复执行恢复动作。
        if let Err(error) = self.clear_account_failures(user_id).await {
            tracing::error!(
                event = "auth_factor.totp.reset_limiter_not_cleared",
                error = %error,
                "TOTP factor was reset but its failure counters were not cleared"
            );
        }
        Ok(TotpResetOutcome::Removed { key_state })
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
    use super::{EncryptionKeyHealth, TotpResetOutcome};
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
}
