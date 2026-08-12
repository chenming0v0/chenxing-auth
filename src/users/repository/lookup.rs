use crate::sqlx::{PgPool, Postgres};
use time::OffsetDateTime;

use crate::users::domain::{LoginIdentifier, UserId, UserRole, UserStatus};
use crate::users::email::EmailAddress;

use super::{ListedUser, UserCredentials, UserProfile};

/// 凭据行：`(id, email, canonical_email, password_hash, password_login_enabled,
/// status, role, session_epoch)`。三个凭据查询只有 WHERE 子句不同，映射逻辑共用
/// 一份，避免角色解析的兜底策略在多处漂移。
///
/// `session_epoch` 与 `password_hash` 必须来自同一行、同一次读取（Issue #274）：
/// 认证结果要绑定"校验所依据的凭据版本"，分两次查询就会在两次读取之间留下
/// 并发改密的窗口，而绑定到一个更新的 epoch 恰好就是被利用的那个漏洞。
type CredentialsRow = (UserId, String, String, String, bool, String, String, i64);

const CREDENTIALS_COLUMNS: &str = "id, email, canonical_email, password_hash, \
     password_login_enabled, status, role, session_epoch";

fn map_credentials(row: CredentialsRow) -> UserCredentials {
    let (
        id,
        email,
        canonical_email,
        password_hash,
        password_login_enabled,
        status,
        role,
        session_epoch,
    ) = row;
    UserCredentials {
        id,
        email,
        canonical_email,
        password_hash,
        password_login_enabled,
        status,
        // 库里出现未知角色时按最小权限降级，不 panic 也不提权。
        role: UserRole::parse(&role).unwrap_or(UserRole::User),
        session_epoch,
    }
}

/// 按登录标识符查凭据。
///
/// 补丁前是 `WHERE email = $1 OR username = $1`，两列共用一个已 ASCII 小写的
/// 字符串。现在邮箱匹配走 `canonical_email`（IDNA + ASCII 小写），用户名匹配走
/// `username`（ASCII 小写 + 字符白名单），两套规则不同，因此按标识符形态分成
/// 两条查询：每条只比一列，都能走各自的唯一索引，也不再有"用邮箱规则算出的串
/// 去比用户名列"这种跨列语义混用（Issue #302）。
pub async fn find_credentials_by_identifier(
    pool: &PgPool,
    identifier: &LoginIdentifier,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    match identifier {
        LoginIdentifier::Email(email) => find_credentials_by_email(pool, email).await,
        LoginIdentifier::Username(username) => crate::sqlx::query_as::<_, CredentialsRow>(
            &format!("SELECT {CREDENTIALS_COLUMNS} FROM users WHERE username = $1"),
        )
        .bind(username)
        .fetch_optional(pool)
        .await
        .map(|record| record.map(map_credentials)),
    }
}

pub async fn find_credentials_by_email(
    pool: &PgPool,
    email: &EmailAddress,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, CredentialsRow>(&format!(
        "SELECT {CREDENTIALS_COLUMNS} FROM users WHERE canonical_email = $1"
    ))
    .bind(email.canonical())
    .fetch_optional(pool)
    .await
    .map(|record| record.map(map_credentials))
}

pub async fn find_credentials_by_id(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, CredentialsRow>(&format!(
        "SELECT {CREDENTIALS_COLUMNS} FROM users WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| record.map(map_credentials))
}

/// 读取 active 用户的当前 `session_epoch`（Issue #409）。
///
/// `None` 表示用户不存在或不是 active 状态。Refresh Token 兑换用它做凭据代际
/// 比对：token 签发时 stamp 进 payload 的 epoch 与当前值不一致，说明期间发生过
/// 改密、管理端 TOTP 重置或禁用等「撤销该用户全部凭据」的操作，凭据必须失效。
pub async fn find_active_session_epoch(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    let row: Option<(i64, String)> =
        crate::sqlx::query_as("SELECT session_epoch, status FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(epoch, status)| {
        (UserStatus::parse(&status) == Some(UserStatus::Active)).then_some(epoch)
    }))
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
