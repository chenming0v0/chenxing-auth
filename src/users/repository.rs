use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::ValidatedRegistration;

#[derive(Debug)]
pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct UserCredentials {
    pub id: Uuid,
    pub password_hash: String,
    pub status: String,
}

#[derive(Debug)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
}

pub async fn insert_user(
    pool: &PgPool,
    registration: ValidatedRegistration,
    password_hash: String,
) -> Result<NewUser, sqlx::Error> {
    let user = NewUser {
        id: Uuid::new_v4(),
        email: registration.email,
        password_hash,
        display_name: registration.display_name,
        created_at: OffsetDateTime::now_utc(),
    };

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, status, created_at)\
         VALUES ($1, $2, $3, $4, 'active', $5)",
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.display_name)
    .bind(user.created_at)
    .execute(pool)
    .await?;

    Ok(user)
}

pub async fn find_credentials_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserCredentials>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, String)>(
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

pub async fn find_profile_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<UserProfile>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, Option<String>, String)>(
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

pub async fn insert_user_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user: &NewUser,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, status, created_at)\
         VALUES ($1, $2, $3, $4, 'active', $5)",
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.display_name)
    .bind(user.created_at)
    .execute(&mut **transaction)
    .await?;

    Ok(())
}
