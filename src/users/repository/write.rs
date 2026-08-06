//! 用户写入路径：插入、资料更新与改密。
//!
//! 与 `owner_bootstrap` 的区别是这里不含 Owner 存在性前提判定；与 `role_guard`
//! 的区别是这里不含"最后一个活跃 Owner"守卫。

use crate::sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::users::domain::{UserId, UserRole, UserStatus, ValidatedRegistration};

use super::NewUser;

pub async fn insert_user(
    pool: &PgPool,
    registration: ValidatedRegistration,
    password_hash: String,
) -> Result<NewUser, crate::sqlx::Error> {
    let username = registration.username;
    let email = registration.email;
    let display_name = registration.display_name;
    let created_at = OffsetDateTime::now_utc();
    let id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, display_name, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', $5, $5)
         RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(&display_name)
    .bind(created_at)
    .fetch_one(pool)
    .await?;

    // 该 SQL 不写 role 列并硬编码 status='active'，返回值必须与落库结果一致，
    // 否则调用方读到的 (role, status) 会与数据库分叉。
    Ok(NewUser {
        id,
        username,
        email,
        password_hash,
        display_name,
        role: UserRole::User,
        status: UserStatus::Active,
        created_at,
    })
}

pub async fn insert_user_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user: &NewUser,
) -> Result<UserId, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, display_name, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', $5, $5)
         RETURNING id",
    )
    .bind(&user.username)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.display_name)
    .bind(user.created_at)
    .fetch_one(&mut **transaction)
    .await
}

pub async fn update_display_name(
    pool: &PgPool,
    id: UserId,
    display_name: Option<&str>,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE users SET display_name = $2 WHERE id = $1")
        .bind(id)
        .bind(display_name)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// 改密并在同一事务里撤销该用户的全部会话。
///
/// 两步必须原子：只改哈希不撤会话会让旧口令泄露后已建立的会话继续有效，
/// 而改密的目的正是切断这些会话。任一步失败即整体回滚。
pub async fn change_password_and_revoke_all(
    pool: &PgPool,
    id: UserId,
    password_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, id).await?;
    let result =
        crate::sqlx::query("UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(password_hash)
            .execute(&mut *transaction)
            .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    if crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, id)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}
