use time::OffsetDateTime;

use super::{
    domain::UserId,
    domain::UserRole,
    repository::{ListedUser, UserPlanSummary},
};
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
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<OffsetDateTime>,
        ),
    >(
        "SELECT u.id, u.username, u.email, u.display_name, u.status, u.role, u.created_at,
                COALESCE(assigned_plan.id, default_plan.id),
                COALESCE(assigned_plan.code, default_plan.code),
                COALESCE(assigned_plan.name, default_plan.name),
                CASE WHEN assigned_plan.id IS NULL THEN NULL ELSE u.plan_expires_at END
         FROM users u
         LEFT JOIN plans assigned_plan
           ON assigned_plan.id = u.plan_id
          AND assigned_plan.status = 'active'
          AND (u.plan_expires_at IS NULL OR u.plan_expires_at > NOW())
         LEFT JOIN plans default_plan
           ON default_plan.is_default = TRUE AND default_plan.status = 'active'
         WHERE ($1::text IS NULL OR u.status = $1)
           AND ($2::text IS NULL OR u.username ILIKE $2 ESCAPE E'\\\\'
                OR u.email ILIKE $2 ESCAPE E'\\\\'
                OR u.display_name ILIKE $2 ESCAPE E'\\\\')
         ORDER BY u.created_at DESC, u.id DESC LIMIT $3 OFFSET $4",
    )
    .bind(status)
    .bind(search_pattern.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(
            id,
            username,
            email,
            display_name,
            status,
            role,
            created_at,
            plan_id,
            plan_code,
            plan_name,
            expires_at,
        )| ListedUser {
            id,
            username,
            email,
            display_name,
            status,
            role: UserRole::parse(&role).unwrap_or(UserRole::User),
            created_at,
            plan: plan_id
                .zip(plan_code)
                .zip(plan_name)
                .map(|((id, code), name)| UserPlanSummary {
                    id,
                    code,
                    name,
                    expires_at,
                }),
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
                    plan: None,
                },
            )
            .collect()
    })
}
