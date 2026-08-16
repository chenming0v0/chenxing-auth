use crate::sqlx::PgPool;
use crate::users::domain::UserId;

// `AppState::new_with_pool` represents an explicitly configured, not-yet-persisted
// Issuer as generation 1. Missing rows must never match later generations.
const INITIAL_ISSUER_GENERATION: i64 = 1;

fn issuer_generation_matches(current: Option<i64>, expected: i64) -> bool {
    current.unwrap_or(INITIAL_ISSUER_GENERATION) == expected
}

#[path = "repository_authenticated.rs"]
mod authenticated;
pub use authenticated::{
    AuthenticatedPasskeyPersistenceResult, AuthenticatedTotpPersistenceResult,
    insert_authenticated_passkey, insert_authenticated_passkey_with_issuer_generation,
    insert_authenticated_totp_factor,
};

#[path = "repository_passkey.rs"]
mod passkey;
pub use passkey::{
    PasskeyPersistOutcome, PasskeyPersistenceResult, PasskeyUpdateOutcome, StoredPasskey,
    count_passkeys, find_passkey_row, insert_passkey_if_empty,
    insert_passkey_if_empty_with_issuer_generation, list_passkeys, list_passkeys_with_versions,
    persist_passkey_authentication, update_passkey,
};

pub async fn insert_totp_factor(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE
         SET encrypted_secret = EXCLUDED.encrypted_secret, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstFactorPersistenceResult {
    Stored,
    AlreadyExists,
}

pub async fn insert_totp_factor_if_empty(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<FirstFactorPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    if account_has_factor(&mut transaction, user_id).await? {
        transaction.commit().await?;
        return Ok(FirstFactorPersistenceResult::AlreadyExists);
    }
    crate::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(FirstFactorPersistenceResult::Stored)
}

pub async fn insert_totp_factor_for_passkey_recovery(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<FirstFactorPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    let passkey_only: bool = crate::sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM user_passkeys WHERE user_id = $1
         ) AND NOT EXISTS(
             SELECT 1 FROM user_totp_factors WHERE user_id = $1
         )",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !passkey_only {
        transaction.commit().await?;
        return Ok(FirstFactorPersistenceResult::AlreadyExists);
    }
    crate::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(FirstFactorPersistenceResult::Stored)
}

/// 惰性重加密的 CAS 更新结果（#360）。
///
/// `bool` 会把「因子已被并发重置/删除」和「并发重加密的无害竞争」压成同一个
/// `false`，调用方于是无从得知读到的密文是否还对应任何现存因子，会继续按
/// 旧密文的明文种子完成认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpCasUpdateOutcome {
    /// 本次写入了替换密文。
    Updated,
    /// 行还在，但密文已被并发写入者替换（同一种子的重加密竞争）：无事可做。
    Superseded,
    /// 行已不存在：因子被并发重置/删除，读到的密文不再代表任何现存因子。
    Missing,
}

pub async fn update_totp_factor_if_current(
    pool: &PgPool,
    user_id: UserId,
    current_ciphertext: &[u8],
    replacement_ciphertext: &[u8],
) -> Result<TotpCasUpdateOutcome, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE user_totp_factors
         SET encrypted_secret = $3, updated_at = NOW()
         WHERE user_id = $1 AND encrypted_secret = $2",
    )
    .bind(user_id)
    .bind(current_ciphertext)
    .bind(replacement_ciphertext)
    .execute(pool)
    .await?;
    if result.rows_affected() == 1 {
        return Ok(TotpCasUpdateOutcome::Updated);
    }
    // CAS 未命中后再查一次存在性，区分「已被并发重加密」（行还在）与
    // 「已被重置/删除」（行没了）。检查与删除之间的残余竞争只会把结果偏向
    // `Missing`，方向是安全的：宁可拒绝，也不按已消失的因子放行。
    let exists: bool = crate::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(if exists {
        TotpCasUpdateOutcome::Superseded
    } else {
        TotpCasUpdateOutcome::Missing
    })
}

pub async fn find_totp_secret(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<Vec<u8>>, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT encrypted_secret FROM user_totp_factors WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub async fn find_totp_factor(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<(Vec<u8>, time::OffsetDateTime)>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Vec<u8>, time::OffsetDateTime)>(
        "SELECT encrypted_secret, updated_at FROM user_totp_factors WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// 删除某个账号的 TOTP 因子。返回 false 表示该账号本来就没有 TOTP。
///
/// 这是 #258 的恢复出口：密文的 kid 退役后种子已经无法解密，也就无法迁移，
/// 唯一能让账号继续可用的动作就是丢弃这份不可读的密文并让用户重新注册。
pub async fn delete_totp_factor(
    pool: &PgPool,
    user_id: UserId,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("DELETE FROM user_totp_factors WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// 在既有事务内删除该账号的全部 Passkey 凭据，返回删除行数（#460）。
///
/// 与 [`delete_totp_factor_in_transaction`] 同一契约：删除与会话撤销必须同事务
/// 提交。返回 `0` 时调用方整体回滚，epoch 推进与 outbox 事件全部撤销。
/// 不 `RETURNING` 凭据材料——管理端只需要「删了几条」，凭据 JSON 不能离开仓储。
pub async fn delete_passkeys_in_transaction(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<i64, crate::sqlx::Error> {
    let result = crate::sqlx::query("DELETE FROM user_passkeys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}

/// 在既有事务内删除 TOTP 因子并取回删除前的密文与更新时间（#331）。
///
/// 管理端重置因子必须与「撤销全部会话」同事务原子提交（Issue #331）：撤销成功而
/// 删除失败会留下「会话已撤、因子未删」的中间态。`RETURNING` 让"这次删除是否真的
/// 发生"变成可观察的事实——返回 `None` 时调用方整体回滚，撤销动作不留痕。
/// 事务化变体不复用 `delete_totp_factor`，因为后者把"没删到"压成 `bool`，
/// 调用方无法区分「账号没有 TOTP」与「删除失败」。
pub async fn delete_totp_factor_in_transaction(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<Option<(Vec<u8>, time::OffsetDateTime)>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Vec<u8>, time::OffsetDateTime)>(
        "DELETE FROM user_totp_factors
         WHERE user_id = $1
         RETURNING encrypted_secret, updated_at",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
}

pub async fn count_totp_factors(pool: &PgPool) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(*) FROM user_totp_factors")
        .fetch_one(pool)
        .await
}

/// 按 user_id 升序取出至多 `limit` 份 TOTP 密文，供管理端统计密钥健康度。
///
/// 只返回密文，由应用层解析信封头部分类；这里不做解密，也不返回 user_id 之外的
/// 任何账号信息。`limit` 由调用方封顶，避免一次把整张表读进内存。
pub async fn list_totp_ciphertexts(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(UserId, Vec<u8>)>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, Vec<u8>)>(
        "SELECT user_id, encrypted_secret FROM user_totp_factors ORDER BY user_id ASC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn find_session_epoch(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

/// 读取账号的邮箱匹配值，用作限流的账号维度键。
///
/// 取 `canonical_email` 而不是 `email`（Issue #302）：第一因子（`users` 服务）用的
/// 是匹配值，第二因子若用展示值，同一个账号在两个阶段会落到两个不同的配额桶。
/// 两者必须是同一个键，否则"账号维度"这个说法就不成立。
pub async fn find_user_canonical_email(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<String>, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT canonical_email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub async fn list_factor_methods(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<String>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, (String,)>(
        "SELECT method FROM (
             SELECT 'totp'::text AS method FROM user_totp_factors WHERE user_id = $1
             UNION ALL
             SELECT 'passkey'::text AS method FROM user_passkeys WHERE user_id = $1
         ) methods ORDER BY method",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(method,)| method).collect())
}

pub async fn has_active_passkey_only_accounts(pool: &PgPool) -> Result<bool, crate::sqlx::Error> {
    list_active_passkey_totp_ciphertexts(pool)
        .await
        .map(|rows| rows.into_iter().any(|ciphertext| ciphertext.is_none()))
}

pub async fn list_active_passkey_totp_ciphertexts<'e, E>(
    executor: E,
) -> Result<Vec<Option<Vec<u8>>>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query_scalar(
        "SELECT t.encrypted_secret
         FROM users u
         JOIN user_passkeys p ON p.user_id = u.id
         LEFT JOIN user_totp_factors t ON t.user_id = u.id
         WHERE u.status = 'active'
         GROUP BY u.id, t.encrypted_secret",
    )
    .fetch_all(executor)
    .await
}

pub async fn has_passkeys<'e, E>(executor: E) -> Result<bool, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_passkeys)")
        .fetch_one(executor)
        .await
}

pub(super) async fn lock_factor_account(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<(), crate::sqlx::Error> {
    crate::db::advisory_lock::lock_user(transaction, user_id).await
}

pub(super) async fn account_has_factor(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM user_totp_factors WHERE user_id = $1
             UNION ALL
             SELECT 1 FROM user_passkeys WHERE user_id = $1
         )",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
}
