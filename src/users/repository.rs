use crate::sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use super::domain::{UserId, ValidatedRegistration};

#[derive(Debug)]
pub struct NewUser {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct UserCredentials {
    pub id: UserId,
    pub password_hash: String,
    pub status: String,
}

#[derive(Debug)]
pub struct UserProfile {
    pub id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
}

#[derive(Debug)]
pub struct ListedUser {
    pub id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: OffsetDateTime,
}

pub async fn insert_user(
    pool: &PgPool,
    registration: ValidatedRegistration,
    password_hash: String,
) -> Result<NewUser, crate::sqlx::Error> {
    let email = registration.email;
    let display_name = registration.display_name;
    let created_at = OffsetDateTime::now_utc();
    let id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users (email, password_hash, display_name, status, created_at)
         VALUES ($1, $2, $3, 'active', $4)
         RETURNING id",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&display_name)
    .bind(created_at)
    .fetch_one(pool)
    .await?;

    Ok(NewUser {
        id,
        email,
        password_hash,
        display_name,
        created_at,
    })
}

pub async fn find_credentials_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, String)>(
        "SELECT id, password_hash, status FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, password_hash, status)| UserCredentials {
            id,
            password_hash,
            status,
        })
    })
}

pub async fn find_credentials_by_id(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<UserCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, String)>(
        "SELECT id, password_hash, status FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, password_hash, status)| UserCredentials {
            id,
            password_hash,
            status,
        })
    })
}

pub async fn find_profile_by_id(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<UserProfile>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, Option<String>, String)>(
        "SELECT id, email, display_name, status FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, email, display_name, status)| UserProfile {
            id,
            email,
            display_name,
            status,
        })
    })
}

pub async fn list_users(pool: &crate::sqlx::PgPool) -> Result<Vec<ListedUser>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (UserId, String, Option<String>, String, OffsetDateTime)>(
        "SELECT id, email, display_name, status, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, email, display_name, status, created_at)| ListedUser {
                id,
                email,
                display_name,
                status,
                created_at,
            })
            .collect()
    })
}

pub async fn set_user_status(
    pool: &crate::sqlx::PgPool,
    id: UserId,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
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

pub async fn update_password_hash(
    pool: &PgPool,
    id: UserId,
    password_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn insert_user_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user: &NewUser,
) -> Result<UserId, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "INSERT INTO users (email, password_hash, display_name, status, created_at)
         VALUES ($1, $2, $3, 'active', $4)
         RETURNING id",
    )
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.display_name)
    .bind(user.created_at)
    .fetch_one(&mut **transaction)
    .await
}
