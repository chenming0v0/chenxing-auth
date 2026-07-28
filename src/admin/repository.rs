use crate::sqlx::PgPool;
use time::OffsetDateTime;

use super::domain::AdminId;

#[derive(Debug)]
pub struct StoredAdmin {
    pub id: AdminId,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub status: String,
}

pub async fn insert(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
    role: &str,
) -> Result<AdminId, crate::sqlx::Error> {
    let id: AdminId = crate::sqlx::query_scalar(
        "INSERT INTO admins (username, password_hash, role, status, created_at)
         VALUES ($1, $2, $3, 'active', $4)
         RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role)
    .bind(OffsetDateTime::now_utc())
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn insert_bootstrap(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
    role: &str,
) -> Result<Option<AdminId>, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(7_341_928_i64)
        .execute(&mut *transaction)
        .await?;
    let initialized: bool = crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admins)")
        .fetch_one(&mut *transaction)
        .await?;
    if initialized {
        transaction.rollback().await?;
        return Ok(None);
    }
    let id: AdminId = crate::sqlx::query_scalar(
        "INSERT INTO admins (username, password_hash, role, status, created_at)
         VALUES ($1, $2, $3, 'active', $4)
         RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role)
    .bind(OffsetDateTime::now_utc())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(id))
}

pub async fn is_initialized(pool: &PgPool) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admins)")
        .fetch_one(pool)
        .await
}

pub async fn find_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (AdminId, String, String, String, String)>(
        "SELECT id, username, password_hash, role, status FROM admins WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, username, password_hash, role, status)| StoredAdmin {
            id,
            username,
            password_hash,
            role,
            status,
        })
    })
}

pub async fn find_by_id(
    pool: &PgPool,
    id: AdminId,
) -> Result<Option<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (AdminId, String, String, String, String)>(
        "SELECT id, username, password_hash, role, status FROM admins WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, username, password_hash, role, status)| StoredAdmin {
            id,
            username,
            password_hash,
            role,
            status,
        })
    })
}

pub async fn touch_login(pool: &PgPool, id: AdminId) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("UPDATE admins SET last_login_at = $2 WHERE id = $1")
        .bind(id)
        .bind(OffsetDateTime::now_utc())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list(pool: &PgPool) -> Result<Vec<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (AdminId, String, String, String, String)>(
        "SELECT id, username, password_hash, role, status FROM admins ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, username, password_hash, role, status)| StoredAdmin {
                id,
                username,
                password_hash,
                role,
                status,
            })
            .collect()
    })
}

pub async fn set_status(
    pool: &PgPool,
    id: AdminId,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE admins SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}
