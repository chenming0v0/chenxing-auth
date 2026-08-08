use crate::sqlx::{PgPool, Postgres};
use time::OffsetDateTime;

use crate::users::domain::{UserId, UserRole};

use super::{ListedUser, UserCredentials, UserProfile};

/// 把 `(id, email, password_hash, password_login_enabled, status, role)` 行映射成
/// `UserCredentials`。两个凭据查询只有 WHERE 子句不同，映射逻辑共用一份，
/// 避免角色解析的兜底策略在两处漂移。
type CredentialsRow = (UserId, String, String, bool, String, String);

fn map_credentials(row: CredentialsRow) -> UserCredentials {
    let (id, email, password_hash, password_login_enabled, status, role) = row;
    UserCredentials {
        id,
        email,
        password_hash,
        password_login_enabled,
        status,
        // 库里出现未知角色时按最小权限降级，不 panic 也不提权。
        role: UserRole::parse(&role).unwrap_or(UserRole::User),
    }
}

pub async fn find_credentials_by_identifier(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, CredentialsRow>(
        "SELECT id, email, password_hash, password_login_enabled, status, role FROM users
         WHERE email = $1 OR username = $1",
    )
    .bind(identifier)
    .fetch_optional(pool)
    .await
    .map(|record| record.map(map_credentials))
}

pub async fn find_credentials_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    find_credentials_by_identifier(pool, email).await
}

pub async fn find_credentials_by_id(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, CredentialsRow>(
        "SELECT id, email, password_hash, password_login_enabled, status, role FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| record.map(map_credentials))
}

/// 泛型 executor 让同一份 profile 映射逻辑既能用连接池，也能在事务内复用。
/// 事务内读取可以看到本事务尚未提交的写入，从而避免"提交后换连接回查"带来的可见性假设。
pub async fn find_profile_by_id<'e, E>(
    executor: E,
    id: UserId,
) -> Result<Option<UserProfile>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = Postgres> + 'e,
{
    crate::sqlx::query_as::<
        _,
        (
            UserId,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<OffsetDateTime>,
        ),
    >(
        "SELECT id, username, email, display_name, status, role, avatar_updated_at
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(executor)
    .await
    .map(|record| {
        record.map(
            |(id, username, email, display_name, status, role, avatar_updated_at)| UserProfile {
                id,
                username,
                email,
                display_name,
                status,
                role: UserRole::parse(&role).unwrap_or(UserRole::User),
                avatar_updated_at,
            },
        )
    })
}

pub async fn list_users(pool: &crate::sqlx::PgPool) -> Result<Vec<ListedUser>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, String, Option<String>, String, String, OffsetDateTime)>(
        "SELECT id, username, email, display_name, status, role, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, username, email, display_name, status, role, created_at)| ListedUser {
                id,
                username,
                email,
                display_name,
                status,
                role: UserRole::parse(&role).unwrap_or(UserRole::User),
                created_at,
                plan: None,
            })
            .collect()
    })
}
