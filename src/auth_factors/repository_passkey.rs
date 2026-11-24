use super::{
    account_has_factor, active_user_epoch_matches, issuer_generation_matches, lock_factor_account,
};
use crate::{sqlx::PgPool, users::domain::UserId};
use webauthn_rs::prelude::Passkey;

#[path = "repository_passkey_authentication.rs"]
mod authentication;
pub use authentication::{PasskeyPersistOutcome, persist_passkey_authentication};

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
#[path = "repository_passkey_tests.rs"]
mod tests;
