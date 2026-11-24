use super::{PasskeyUpdateOutcome, find_passkey_row, update_passkey};
use crate::{sqlx::PgPool, users::domain::UserId};
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

/// 单次 CAS 重试上限；耗尽后不能把未持久化的安全状态当成认证成功。
const PASSKEY_CAS_ATTEMPTS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyPersistOutcome {
    Applied,
    /// 计数均为零且凭据安全状态无需更新，兼容不提供计数的同步 Passkey。
    AlreadyCurrent,
    /// 非零计数没有超过最新持久化值，本次认证必须用新 challenge 重试。
    CounterConflict,
    /// 行已删除或同一 credential_id 已重新注册到另一行。
    Missing,
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PasskeyMergeOutcome {
    Changed,
    Unchanged,
    Mismatch,
}

#[derive(serde::Deserialize)]
struct PasskeyCounter {
    cred: CredentialCounter,
}

#[derive(serde::Deserialize)]
struct CredentialCounter {
    counter: u32,
}

fn stored_counter(passkey: &Passkey) -> Result<u32, crate::sqlx::Error> {
    let value = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    serde_json::from_value::<PasskeyCounter>(value)
        .map(|passkey| passkey.cred.counter)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))
}

/// 在每轮 CAS 前复核最新计数，不能仅依赖 challenge 中的旧凭据快照。
/// 计数乱序也可能来自正常并发，因此只要求重新认证，不判定克隆或停用凭据。
pub async fn persist_passkey_authentication(
    pool: &PgPool,
    user_id: UserId,
    row_id: i64,
    credential_id: &[u8],
    result: &AuthenticationResult,
) -> Result<PasskeyPersistOutcome, crate::sqlx::Error> {
    for _ in 0..PASSKEY_CAS_ATTEMPTS {
        let Some(mut stored) = find_passkey_row(pool, user_id, row_id).await? else {
            return Ok(PasskeyPersistOutcome::Missing);
        };
        if stored.credential_id != credential_id || stored.credential.cred_id() != result.cred_id()
        {
            return Ok(PasskeyPersistOutcome::Missing);
        }
        let current_counter = stored_counter(&stored.credential)?;
        let asserted_counter = result.counter();
        if (current_counter != 0 || asserted_counter != 0) && asserted_counter <= current_counter {
            tracing::warn!(
                event = "auth_factor.passkey.counter_conflict",
                user_id,
                passkey_row_id = row_id,
                current_counter,
                asserted_counter,
                "Passkey counter did not advance; a fresh authentication challenge is required"
            );
            return Ok(PasskeyPersistOutcome::CounterConflict);
        }
        // needs_update 也是基于旧 challenge 算出的提示，不能跳过当前计数复核或合并。
        match apply_authentication_result(&mut stored.credential, result) {
            PasskeyMergeOutcome::Mismatch => return Ok(PasskeyPersistOutcome::Missing),
            PasskeyMergeOutcome::Unchanged => return Ok(PasskeyPersistOutcome::AlreadyCurrent),
            PasskeyMergeOutcome::Changed => match update_passkey(
                pool,
                user_id,
                stored.id,
                &stored.credential_id,
                stored.state_version,
                &stored.credential,
            )
            .await?
            {
                PasskeyUpdateOutcome::Updated => return Ok(PasskeyPersistOutcome::Applied),
                PasskeyUpdateOutcome::Missing => return Ok(PasskeyPersistOutcome::Missing),
                PasskeyUpdateOutcome::Conflict => continue,
            },
        }
    }
    Ok(PasskeyPersistOutcome::Exhausted)
}

pub(super) fn apply_authentication_result(
    stored: &mut Passkey,
    result: &AuthenticationResult,
) -> PasskeyMergeOutcome {
    match stored.update_credential(result) {
        Some(true) => PasskeyMergeOutcome::Changed,
        Some(false) => PasskeyMergeOutcome::Unchanged,
        None => PasskeyMergeOutcome::Mismatch,
    }
}
