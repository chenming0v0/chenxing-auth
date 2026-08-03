use time::OffsetDateTime;

use super::{domain::UserId, domain::UserRole, repository::ListedUser};
use crate::sqlx::PgPool;

#[derive(Debug)]
pub struct UserCounts {
    pub total: i64,
    pub administrators: i64,
}

pub async fn query_users(
    pool: &PgPool,
    search: Option<&str>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ListedUser>, i64), crate::sqlx::Error> {
    let search_pattern = search.map(|value| {
        format!(
            "%{}%",
            value
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let total = crate::sqlx::query_scalar(
        "SELECT COUNT(*) FROM users
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR username ILIKE $2 ESCAPE E'\\\\'
                OR email ILIKE $2 ESCAPE E'\\\\'
                OR display_name ILIKE $2 ESCAPE E'\\\\')",
    )
    .bind(status)
    .bind(search_pattern.as_deref())
    .fetch_one(pool)
    .await?;
    let rows = crate::sqlx::query_as::<
        _,
        (
            UserId,
            String,
            String,
            Option<String>,
            String,
            String,
            OffsetDateTime,
        ),
    >(
        "SELECT id, username, email, display_name, status, role, created_at
         FROM users
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR username ILIKE $2 ESCAPE E'\\\\'
                OR email ILIKE $2 ESCAPE E'\\\\'
                OR display_name ILIKE $2 ESCAPE E'\\\\')
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(status)
    .bind(search_pattern.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(id, username, email, display_name, status, role, created_at)| ListedUser {
            id,
            username,
            email,
            display_name,
            status,
            role: UserRole::parse(&role).unwrap_or(UserRole::User),
            created_at,
        },
    )
    .collect();
    Ok((rows, total))
}

pub async fn count_users(pool: &PgPool) -> Result<UserCounts, crate::sqlx::Error> {
    let (total, administrators) = crate::sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE role IN ('admin', 'owner')) FROM users",
    )
    .fetch_one(pool)
    .await?;
    Ok(UserCounts {
        total,
        administrators,
    })
}

pub async fn list_administrators(pool: &PgPool) -> Result<Vec<ListedUser>, crate::sqlx::Error> {
    crate::sqlx::query_as::<
        _,
        (
            UserId,
            String,
            String,
            Option<String>,
            String,
            String,
            OffsetDateTime,
        ),
    >(
        "SELECT id, username, email, display_name, status, role, created_at
         FROM users WHERE role IN ('admin', 'owner') ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(id, username, email, display_name, status, role, created_at)| ListedUser {
                    id,
                    username,
                    email,
                    display_name,
                    status,
                    role: UserRole::parse(&role).unwrap_or(UserRole::User),
                    created_at,
                },
            )
            .collect()
    })
}
