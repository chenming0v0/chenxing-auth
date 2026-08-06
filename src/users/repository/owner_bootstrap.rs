//! Owner 引导与受 Owner 前提约束的用户创建。
//!
//! 两个函数都检查 Owner 是否已存在，逻辑集中在这一层：
//! - `bootstrap_owner`：不存在时创建首个 Owner，否则拒绝。
//! - `insert_user_after_owner`：已存在时按 `UserCreation` 的角色与状态创建，
//!   否则拒绝。公开注册、管理侧创建和特权用户创建共用它，差异只在传入的
//!   (role, status)，不再各自维护一份带 Owner 前提的插入 SQL。

use crate::sqlx::{PgPool, Postgres};
use time::OffsetDateTime;

use crate::users::domain::{UserCreation, UserId};

use super::{NewUser, UserProfile};

/// Owner 是否已存在。
///
/// 这条 EXISTS 判定同时服务三类调用者：Owner 引导事务、受限注册事务和只读的
/// 初始化探测接口。它们对执行器的要求不同（事务内必须看到本事务未提交的写入，
/// 探测接口只需要连接池），所以按 `find_profile_by_id` 的方式收成泛型 executor，
/// 而不是让 SQL 散落在服务层和多个事务分支里各写一遍。
pub async fn owner_exists<'e, E>(executor: E) -> Result<bool, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = Postgres> + 'e,
{
    crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
        .fetch_one(executor)
        .await
}

/// users 表是否为空之外的任意一行存在。
///
/// 仅供 Owner 引导判定"数据库是否已经被使用过"，与 `owner_exists` 分开是因为两者
/// 表达的业务前提不同：一个是"有没有 Owner"，一个是"这个库是不是全新的"。
async fn any_user_exists<'e, E>(executor: E) -> Result<bool, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = Postgres> + 'e,
{
    crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users)")
        .fetch_one(executor)
        .await
}

/// 在 Owner 已存在的前提下创建用户。
///
/// 返回 `Ok(None)` 表示尚未完成 Owner 引导：advisory lock 与引导事务用同一个
/// key，因此"判定 Owner 存在"与"插入新用户"之间不存在竞态窗口，
/// 引导中途不会有用户被插进一个还没有 Owner 的库。
pub async fn insert_user_after_owner(
    pool: &PgPool,
    creation: UserCreation,
    password_hash: String,
) -> Result<Option<NewUser>, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341928)")
        .execute(&mut *transaction)
        .await?;
    if !owner_exists(&mut *transaction).await? {
        transaction.rollback().await?;
        return Ok(None);
    }

    let UserCreation {
        registration,
        role,
        status,
    } = creation;
    let username = registration.username;
    let email = registration.email;
    let display_name = registration.display_name;
    let created_at = OffsetDateTime::now_utc();
    let id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, display_name, role, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
         RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(&display_name)
    .bind(role.as_str())
    .bind(status.as_str())
    .bind(created_at)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Some(NewUser {
        id,
        username,
        email,
        password_hash,
        display_name,
        role,
        status,
        created_at,
    }))
}

pub async fn bootstrap_owner(
    pool: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
) -> Result<BootstrapOwnerOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341928)")
        .execute(&mut *transaction)
        .await?;
    if owner_exists(&mut *transaction).await? {
        transaction.rollback().await?;
        return Ok(BootstrapOwnerOutcome::AlreadyConfigured);
    }
    if any_user_exists(&mut *transaction).await? {
        transaction.rollback().await?;
        return Ok(BootstrapOwnerOutcome::RequiresEmptyDatabase);
    }
    crate::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), 1, false)")
        .execute(&mut *transaction)
        .await?;
    let id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, role, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'owner', 'active', NOW(), NOW()) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .fetch_one(&mut *transaction)
    .await?;
    // 在同一事务内回查：事务必然看到自己刚插入的行，不依赖"提交后对新连接立即可见"这一假设，
    // 因此读写分离、只读副本路由或复制延迟都不会让这里读空。
    // 仍然显式处理 None 而不是 expect：Owner 初始化是一次性高价值路径，
    // 宁可返回明确的数据库错误，也不要在 handler 调用栈里 panic。
    let profile = super::lookup::find_profile_by_id(&mut *transaction, id)
        .await?
        .ok_or(crate::sqlx::Error::RowNotFound)?;
    transaction.commit().await?;
    Ok(BootstrapOwnerOutcome::Created(profile))
}

#[derive(Debug)]
pub enum BootstrapOwnerOutcome {
    Created(UserProfile),
    AlreadyConfigured,
    RequiresEmptyDatabase,
}
