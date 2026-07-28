use crate::sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct StoredAdmin {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub status: String,
}

pub async fn insert(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    role: &str,
) -> Result<Uuid, crate::sqlx::Error> {
    let id = Uuid::new_v4();
    crate::sqlx::query(
        "INSERT INTO admins (id, email, password_hash, role, status, created_at)
         VALUES ($1, $2, $3, $4, 'active', $5)",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn insert_bootstrap(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    role: &str,
) -> Result<Option<Uuid>, crate::sqlx::Error> {
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
    let id = Uuid::new_v4();
    crate::sqlx::query(
        "INSERT INTO admins (id, email, password_hash, role, status, created_at)
         VALUES ($1, $2, $3, $4, 'active', $5)",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(id))
}

pub async fn find_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Uuid, String, String, String, String)>(
        "SELECT id, email, password_hash, role, status FROM admins WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, email, password_hash, role, status)| StoredAdmin {
            id,
            email,
            password_hash,
            role,
            status,
        })
    })
}

pub async fn find_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Uuid, String, String, String, String)>(
        "SELECT id, email, password_hash, role, status FROM admins WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(id, email, password_hash, role, status)| StoredAdmin {
            id,
            email,
            password_hash,
            role,
            status,
        })
    })
}

pub async fn touch_login(pool: &PgPool, id: Uuid) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("UPDATE admins SET last_login_at = $2 WHERE id = $1")
        .bind(id)
        .bind(OffsetDateTime::now_utc())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list(pool: &PgPool) -> Result<Vec<StoredAdmin>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Uuid, String, String, String, String)>(
        "SELECT id, email, password_hash, role, status FROM admins ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|(id, email, password_hash, role, status)| StoredAdmin {
                id,
                email,
                password_hash,
                role,
                status,
            })
            .collect()
    })
}

pub async fn set_status(pool: &PgPool, id: Uuid, status: &str) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE admins SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}
