use super::{
    account_has_factor, active_user_epoch_matches, issuer_generation_matches, lock_factor_account,
};
use crate::{sqlx::PgPool, users::domain::UserId};
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

/// 单次 CAS 重试上限。超过后返回 [`PasskeyPersistOutcome::Exhausted`]，
/// 绝不把“没写进去”伪装成成功。
const PASSKEY_CAS_ATTEMPTS: u32 = 8;

#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub id: i64,
    pub credential_id: Vec<u8>,
    pub credential: Passkey,
    pub state_version: i64,
}

impl StoredPasskey {
    pub fn cred_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub fn passkey(&self) -> &Passkey {
        &self.credential
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyPersistenceResult {
    Stored,
    Conflict,
    IssuerChanged,
    /// Ticket 上盖的 epoch 已不是当前值，或账号已不是 active。
    AuthenticationChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyUpdateOutcome {
    Updated,
    Conflict,
    Missing,
}

/// 认证后把 `AuthenticationResult` 合并进当前行的结果。
///
/// `Updated` 会被压扁成布尔值，调用方就分不清“已经是更新的安全状态”
/// 和“行已经没了”。这两种情况绝不能走同一条成功路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyPersistOutcome {
    /// 本次 CAS 写入了合并后的凭据。
    Applied,
    /// 行还在，webauthn-rs 规则判定当前安全状态已经覆盖这次结果。
    AlreadyCurrent,
    /// 行已不存在，或 `id` 对应的已不是签发 challenge 时的那一行
    /// （删除后用同一 `credential_id` 重新注册）。
    Missing,
    /// 有限次重读合并后仍抢不到 CAS：不能假装成功。
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyMergeOutcome {
    Changed,
    Unchanged,
    Mismatch,
}

pub async fn list_passkeys(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<Passkey>, crate::sqlx::Error> {
    Ok(list_passkeys_with_versions(pool, user_id)
        .await?
        .into_iter()
        .map(|stored| stored.credential)
        .collect())
}

pub async fn list_passkeys_with_versions(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<StoredPasskey>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, (i64, Vec<u8>, serde_json::Value, i64)>(
        "SELECT id, credential_id, credential, state_version
         FROM user_passkeys WHERE user_id = $1 ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(id, credential_id, value, state_version)| {
            decode_stored_passkey(id, credential_id, value, state_version)
        })
        .collect()
}

pub async fn find_passkey_row(
    pool: &PgPool,
    user_id: UserId,
    row_id: i64,
) -> Result<Option<StoredPasskey>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, (i64, Vec<u8>, serde_json::Value, i64)>(
        "SELECT id, credential_id, credential, state_version
         FROM user_passkeys WHERE id = $1 AND user_id = $2",
    )
    .bind(row_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    row.map(|(id, credential_id, value, state_version)| {
        decode_stored_passkey(id, credential_id, value, state_version)
    })
    .transpose()
}

pub async fn count_passkeys(pool: &PgPool, user_id: UserId) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(*) FROM user_passkeys WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

pub async fn insert_passkey_if_empty(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
) -> Result<PasskeyPersistenceResult, crate::sqlx::Error> {
    insert_passkey_if_empty_with_generation(
        pool,
        user_id,
        expected_session_epoch,
        credential_id,
        passkey,
        None,
    )
    .await
}

pub async fn insert_passkey_if_empty_with_issuer_generation(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
    expected_issuer_generation: i64,
) -> Result<PasskeyPersistenceResult, crate::sqlx::Error> {
    insert_passkey_if_empty_with_generation(
        pool,
        user_id,
        expected_session_epoch,
        credential_id,
        passkey,
        Some(expected_issuer_generation),
    )
    .await
}

async fn insert_passkey_if_empty_with_generation(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
    expected_issuer_generation: Option<i64>,
) -> Result<PasskeyPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::settings::repository::lock_passkey_policy(&mut transaction).await?;
    if let Some(expected) = expected_issuer_generation {
        let current: Option<i64> = crate::sqlx::query_scalar(
            "SELECT generation FROM app_settings WHERE setting_key = 'app_issuer'",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        if !issuer_generation_matches(current, expected) {
            transaction.rollback().await?;
            return Ok(PasskeyPersistenceResult::IssuerChanged);
        }
    }
    let enabled = match crate::settings::repository::get_text(
        &mut *transaction,
        crate::settings::PASSKEY_KEY,
    )
    .await?
    {
        None => true,
        Some(raw) => serde_json::from_str::<crate::settings::PasskeySetting>(&raw)
            .map(|setting| setting.enabled)
            .unwrap_or(false),
    };
    if !enabled {
        transaction.commit().await?;
        return Ok(PasskeyPersistenceResult::Conflict);
    }
    lock_factor_account(&mut transaction, user_id).await?;
    if !active_user_epoch_matches(&mut transaction, user_id, expected_session_epoch).await? {
        transaction.rollback().await?;
        return Ok(PasskeyPersistenceResult::AuthenticationChanged);
    }
    if account_has_factor(&mut transaction, user_id).await? {
        transaction.commit().await?;
        return Ok(PasskeyPersistenceResult::Conflict);
    }
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    let result = crate::sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (credential_id) DO NOTHING
         RETURNING user_id",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(credential)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(if result.is_some() {
        PasskeyPersistenceResult::Stored
    } else {
        PasskeyPersistenceResult::Conflict
    })
}

/// 按行身份做 CAS：`id + user_id + credential_id + expected_version`。
///
/// 存在性检查必须按 `id`，不能按 `credential_id`。删除后用同一凭据重新注册
/// 会生成新行、`state_version` 从 1 重新开始；按 cred_id 判断会把“旧请求打到
/// 新行”误判成 Conflict，随后重试还可能写进新行。
pub async fn update_passkey(
    pool: &PgPool,
    user_id: UserId,
    row_id: i64,
    credential_id: &[u8],
    expected_version: i64,
    passkey: &Passkey,
) -> Result<PasskeyUpdateOutcome, crate::sqlx::Error> {
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    let result = crate::sqlx::query(
        "UPDATE user_passkeys
         SET credential = $5, state_version = state_version + 1, updated_at = NOW()
         WHERE id = $1 AND user_id = $2 AND credential_id = $3 AND state_version = $4",
    )
    .bind(row_id)
    .bind(user_id)
    .bind(credential_id)
    .bind(expected_version)
    .bind(credential)
    .execute(pool)
    .await?;
    if result.rows_affected() == 1 {
        return Ok(PasskeyUpdateOutcome::Updated);
    }
    let exists: bool = crate::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_passkeys WHERE id = $1 AND user_id = $2)",
    )
    .bind(row_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(if exists {
        PasskeyUpdateOutcome::Conflict
    } else {
        PasskeyUpdateOutcome::Missing
    })
}

/// 把一次已验签的 `AuthenticationResult` 合并进指定行。
///
/// 冲突时按行 `id` 重读，再用 webauthn-rs 的单调/克隆检测规则合并，
/// 禁止把基于过期 JSON 的更新原样重放上去。
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
        if stored.credential_id != credential_id {
            return Ok(PasskeyPersistOutcome::Missing);
        }
        if !result.needs_update() {
            return Ok(PasskeyPersistOutcome::AlreadyCurrent);
        }
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

pub(crate) fn apply_authentication_result(
    stored: &mut Passkey,
    result: &AuthenticationResult,
) -> PasskeyMergeOutcome {
    match stored.update_credential(result) {
        Some(true) => PasskeyMergeOutcome::Changed,
        Some(false) => PasskeyMergeOutcome::Unchanged,
        None => PasskeyMergeOutcome::Mismatch,
    }
}

fn decode_stored_passkey(
    id: i64,
    credential_id: Vec<u8>,
    value: serde_json::Value,
    state_version: i64,
) -> Result<StoredPasskey, crate::sqlx::Error> {
    let credential = serde_json::from_value(value)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))?;
    Ok(StoredPasskey {
        id,
        credential_id,
        credential,
        state_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn encode(value: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
    }

    fn test_passkey(credential_id: &[u8], counter: u32, backup_eligible: bool) -> Passkey {
        serde_json::from_value(serde_json::json!({
            "cred": {
                "cred_id": encode(credential_id),
                "cred": {
                    "type_": "ES256",
                    "key": {
                        "EC_EC2": {
                            "curve": "SECP256R1",
                            "x": encode(&[4; 32]),
                            "y": encode(&[5; 32])
                        }
                    }
                },
                "counter": counter,
                "transports": null,
                "user_verified": false,
                "backup_eligible": backup_eligible,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {"data": "None", "metadata": "None"},
                "attestation_format": "none"
            }
        }))
        .expect("test passkey")
    }

    fn authentication_result(
        credential_id: &[u8],
        counter: u32,
        backup_eligible: bool,
        backup_state: bool,
    ) -> AuthenticationResult {
        serde_json::from_value(serde_json::json!({
            "cred_id": encode(credential_id),
            "needs_update": true,
            "user_verified": true,
            "backup_state": backup_state,
            "backup_eligible": backup_eligible,
            "counter": counter,
            "extensions": {}
        }))
        .expect("authentication result")
    }

    fn counter_of(passkey: &Passkey) -> u32 {
        serde_json::to_value(passkey).expect("passkey JSON")["cred"]["counter"]
            .as_u64()
            .expect("counter") as u32
    }

    fn backup_eligible_of(passkey: &Passkey) -> bool {
        serde_json::to_value(passkey).expect("passkey JSON")["cred"]["backup_eligible"]
            .as_bool()
            .expect("backup_eligible")
    }

    #[test]
    fn absent_issuer_row_matches_only_the_initial_runtime_generation() {
        let initial = super::super::INITIAL_ISSUER_GENERATION;
        assert!(issuer_generation_matches(None, initial));
        assert!(!issuer_generation_matches(None, initial + 1));
    }

    #[test]
    fn merge_keeps_newer_counter_when_stale_result_arrives_later() {
        let credential_id = b"cred-1";
        let mut stored = test_passkey(credential_id, 2, false);
        let stale = authentication_result(credential_id, 1, false, false);
        assert_eq!(
            apply_authentication_result(&mut stored, &stale),
            PasskeyMergeOutcome::Unchanged
        );
        assert_eq!(counter_of(&stored), 2);
    }

    #[test]
    fn merge_applies_newer_counter_onto_older_stored_state() {
        let credential_id = b"cred-1";
        let mut stored = test_passkey(credential_id, 1, false);
        let newer = authentication_result(credential_id, 2, false, false);
        assert_eq!(
            apply_authentication_result(&mut stored, &newer),
            PasskeyMergeOutcome::Changed
        );
        assert_eq!(counter_of(&stored), 2);
    }

    #[test]
    fn merge_can_raise_backup_eligible_without_rewinding_counter() {
        let credential_id = b"cred-1";
        let mut stored = test_passkey(credential_id, 4, false);
        let stale_with_upgrade = authentication_result(credential_id, 3, true, true);
        assert_eq!(
            apply_authentication_result(&mut stored, &stale_with_upgrade),
            PasskeyMergeOutcome::Changed
        );
        assert_eq!(counter_of(&stored), 4);
        assert!(backup_eligible_of(&stored));
    }

    #[test]
    fn merge_rejects_result_for_a_different_credential() {
        let mut stored = test_passkey(b"cred-1", 1, false);
        let other = authentication_result(b"cred-2", 2, false, false);
        assert_eq!(
            apply_authentication_result(&mut stored, &other),
            PasskeyMergeOutcome::Mismatch
        );
        assert_eq!(counter_of(&stored), 1);
    }
}
