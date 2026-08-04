use crate::sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use super::domain::{UserId, UserRole, ValidatedRegistration};

#[derive(Debug)]
pub struct NewUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct UserCredentials {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
    pub password_login_enabled: bool,
    pub status: String,
    pub role: UserRole,
}

#[derive(Debug)]
pub struct UserProfile {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
}

#[derive(Debug)]
pub struct UserPlanSummary {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub struct ListedUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
    pub created_at: OffsetDateTime,
    pub plan: Option<UserPlanSummary>,
}

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

    Ok(NewUser {
        id,
        username,
        email,
        password_hash,
        display_name,
        created_at,
    })
}

pub async fn insert_user_after_owner(
    pool: &PgPool,
    registration: ValidatedRegistration,
    password_hash: String,
) -> Result<Option<NewUser>, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341928)")
        .execute(&mut *transaction)
        .await?;
    let owner_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
            .fetch_one(&mut *transaction)
            .await?;
    if !owner_exists {
        transaction.rollback().await?;
        return Ok(None);
    }

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
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Some(NewUser {
        id,
        username,
        email,
        password_hash,
        display_name,
        created_at,
    }))
}

pub async fn find_credentials_by_identifier(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, String, bool, String, String)>(
        "SELECT id, email, password_hash, password_login_enabled, status, role FROM users
         WHERE email = $1 OR username = $1",
    )
    .bind(identifier)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(
            |(id, email, password_hash, password_login_enabled, status, role)| UserCredentials {
                id,
                email,
                password_hash,
                password_login_enabled,
                status,
                role: UserRole::parse(&role).unwrap_or(UserRole::User),
            },
        )
    })
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
    crate::sqlx::query_as::<_, (UserId, String, String, bool, String, String)>(
        "SELECT id, email, password_hash, password_login_enabled, status, role FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(
            |(id, email, password_hash, password_login_enabled, status, role)| UserCredentials {
                id,
                email,
                password_hash,
                password_login_enabled,
                status,
                role: UserRole::parse(&role).unwrap_or(UserRole::User),
            },
        )
    })
}

pub async fn find_profile_by_id(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<UserProfile>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, String, Option<String>, String, String)>(
        "SELECT id, username, email, display_name, status, role FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(
            |(id, username, email, display_name, status, role)| UserProfile {
                id,
                username,
                email,
                display_name,
                status,
                role: UserRole::parse(&role).unwrap_or(UserRole::User),
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

pub async fn set_user_status(
    pool: &crate::sqlx::PgPool,
    id: UserId,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    Ok(matches!(
        set_user_status_guarded(pool, id, status).await?,
        Some("updated")
    ))
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
    let owner_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
            .fetch_one(&mut *transaction)
            .await?;
    if owner_exists {
        transaction.rollback().await?;
        return Ok(BootstrapOwnerOutcome::AlreadyConfigured);
    }
    let users_exist: bool = crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users)")
        .fetch_one(&mut *transaction)
        .await?;
    if users_exist {
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
    transaction.commit().await?;
    Ok(BootstrapOwnerOutcome::Created(
        find_profile_by_id(pool, id)
            .await?
            .expect("inserted owner must exist"),
    ))
}

#[derive(Debug)]
pub enum BootstrapOwnerOutcome {
    Created(UserProfile),
    AlreadyConfigured,
    RequiresEmptyDatabase,
}

pub async fn insert_user_with_role(
    pool: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
    role: UserRole,
) -> Result<Option<UserId>, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341928)")
        .execute(&mut *transaction)
        .await?;
    let owner_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
            .fetch_one(&mut *transaction)
            .await?;
    if !owner_exists {
        transaction.rollback().await?;
        return Ok(None);
    }
    let id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, role, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', NOW(), NOW()) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(role.as_str())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(id))
}

pub async fn set_user_role(
    pool: &PgPool,
    id: UserId,
    role: UserRole,
) -> Result<bool, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let active_owners: Vec<(UserId,)> = crate::sqlx::query_as(
        "SELECT id FROM users WHERE role = 'owner' AND status = 'active' ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *transaction)
    .await?;
    let current: Option<(String, String)> =
        crate::sqlx::query_as("SELECT role, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some((current_role, status)) = current else {
        transaction.rollback().await?;
        return Ok(false);
    };
    if current_role == "owner"
        && role != UserRole::Owner
        && status == "active"
        && active_owners.len() <= 1
    {
        transaction.rollback().await?;
        return Err(crate::sqlx::Error::Protocol(
            "last active owner required".to_owned(),
        ));
    }
    crate::sqlx::query("UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn set_user_status_guarded(
    pool: &PgPool,
    id: UserId,
    status: &str,
) -> Result<Option<&'static str>, crate::sqlx::Error> {
    if !matches!(status, "active" | "disabled") {
        return Ok(None);
    }
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, id).await?;
    let active_owners: Vec<(UserId,)> = crate::sqlx::query_as(
        "SELECT id FROM users WHERE role = 'owner' AND status = 'active' ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *transaction)
    .await?;
    let current: Option<(String, String)> =
        crate::sqlx::query_as("SELECT role, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some((role, current_status)) = current else {
        transaction.rollback().await?;
        return Ok(None);
    };
    if role == "owner"
        && current_status == "active"
        && status == "disabled"
        && active_owners.len() <= 1
    {
        transaction.rollback().await?;
        return Ok(Some("last_owner_required"));
    }
    if current_status != status && status == "disabled" {
        crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, id).await?;
    }
    let result =
        crate::sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(&mut *transaction)
            .await?;
    transaction.commit().await?;
    Ok((result.rows_affected() == 1).then_some("updated"))
}
