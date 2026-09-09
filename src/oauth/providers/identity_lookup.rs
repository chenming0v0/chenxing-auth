//! 外部身份的查找与自动建号。
//!
//! 从 `repository` 拆出：provider 配置的 CRUD 留在 `repository`，身份事实
//! （登录查找、首登建号）集中在这里，经 `repository` 的 `pub use` 保持
//! 原有 `repository::find_identity` 等路径不变。

use crate::sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::identity_repository::subject_hint;
use crate::db::advisory_lock::{BusinessLock, lock_business};
use crate::users::domain::{UserId, UserStatus};
use crate::users::email::EmailAddress;
use crate::users::email_policy::evaluate_email_policy;

#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: i64,
    pub provider_id: i64,
    pub user_id: UserId,
    pub subject: String,
    pub email: String,
    pub user_status: String,
}

pub async fn find_identity(
    pool: &PgPool,
    provider_id: i64,
    subject: &str,
) -> Result<Option<ExternalIdentity>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (i64, i64, UserId, String, String, String)>(
        "SELECT i.id, i.provider_id, i.user_id, i.subject, i.email, u.status
         FROM oauth_external_identities i
         JOIN users u ON u.id = i.user_id
         WHERE i.provider_id = $1 AND i.subject = $2",
    )
    .bind(provider_id)
    .bind(subject)
    .fetch_optional(pool)
    .await
    .map(|row| {
        row.map(
            |(id, provider_id, user_id, subject, email, user_status)| ExternalIdentity {
                id,
                provider_id,
                user_id,
                subject,
                email,
                user_status,
            },
        )
    })
}

pub async fn create_user_with_identity(
    pool: &PgPool,
    provider_id: i64,
    email: &EmailAddress,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    subject: &str,
    password_hash: &str,
) -> Result<UserId, CreateIdentityError> {
    let mut transaction = pool.begin().await?;
    lock_business(&mut transaction, BusinessLock::OwnerBootstrap).await?;
    let existing_identity: Option<(UserId, String)> = crate::sqlx::query_as(
        "SELECT i.user_id, u.status
         FROM oauth_external_identities i
         JOIN users u ON u.id = i.user_id
         WHERE i.provider_id = $1 AND i.subject = $2
         FOR UPDATE OF i, u",
    )
    .bind(provider_id)
    .bind(subject)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((user_id, status)) = existing_identity {
        transaction.rollback().await?;
        if UserStatus::parse(&status) != Some(UserStatus::Active) {
            return Err(CreateIdentityError::UserDisabled);
        }
        return Ok(user_id);
    }

    // 按匹配值查重（Issue #302）：IdP 换一种书写返回同一个邮箱时，这里必须仍然
    // 认出"已注册"，否则会绕过展示值上的 UNIQUE 建出第二个账号。
    let existing_user: Option<UserId> =
        crate::sqlx::query_scalar("SELECT id FROM users WHERE canonical_email = $1 FOR UPDATE")
            .bind(email.canonical())
            .fetch_optional(&mut *transaction)
            .await?;
    if existing_user.is_some() {
        transaction.rollback().await?;
        return Err(CreateIdentityError::EmailAlreadyRegistered);
    }

    // 外部身份自动建号与普通注册共用同一准入策略（Issue #550）。读取和判定
    // 必须发生在创建事务内，并且位于任何 INSERT 之前：策略拒绝、损坏配置或
    // 后续数据库错误都不能留下 users / oauth_external_identities 半成品。
    let email_policy_raw =
        crate::settings::repository::get_text(&mut *transaction, crate::settings::EMAIL_POLICY_KEY)
            .await?;
    if evaluate_email_policy(email_policy_raw, email).is_err() {
        transaction.rollback().await?;
        return Err(CreateIdentityError::EmailPolicyRejected);
    }

    let owner_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
            .fetch_one(&mut *transaction)
            .await?;
    if !owner_exists {
        transaction.rollback().await?;
        return Err(CreateIdentityError::OwnerBootstrapRequired);
    }

    let username = format!("oauth_{}", Uuid::new_v4().simple());
    // 保留墙钟（Issue #299 的明确例外）：新用户与身份绑定的行创建时间。
    let now = OffsetDateTime::now_utc();
    let user_id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users
         (username, email, canonical_email, password_hash, password_login_enabled, display_name, status, created_at)
         VALUES ($1, $2, $3, $4, FALSE, $5, 'active', $6)
         RETURNING id",
    )
    .bind(username)
    .bind(email.display())
    .bind(email.canonical())
    .bind(password_hash)
    .bind(display_name)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    // 外部身份表上的 email 是建号那一刻的展示快照，没有唯一约束也不参与匹配；
    // 身份的唯一键是 (provider_id, subject)。
    crate::sqlx::query(
        "INSERT INTO oauth_external_identities
         (provider_id, user_id, subject, email, created_at, updated_at,
          account_name, avatar_url, subject_hint, last_synced_at, sync_status, extensions)
         VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $5, 'success', '[]'::jsonb)",
    )
    .bind(provider_id)
    .bind(user_id)
    .bind(subject)
    .bind(email.display())
    .bind(now)
    .bind(display_name)
    .bind(avatar_url)
    .bind(subject_hint(subject))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(user_id)
}

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentityError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("email is already registered")]
    EmailAlreadyRegistered,
    #[error("email is not allowed by the registration policy")]
    EmailPolicyRejected,
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required before creating external users")]
    OwnerBootstrapRequired,
}
