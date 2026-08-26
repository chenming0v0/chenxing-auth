use time::OffsetDateTime;

use super::redemption_domain::{RedemptionCodeSummary, RedemptionUse};
use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::domain::UserId;

pub type SummaryRow = (
    i64,
    Option<String>,
    i64,
    i32,
    i32,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    OffsetDateTime,
);

pub fn summary(row: SummaryRow) -> RedemptionCodeSummary {
    RedemptionCodeSummary {
        id: row.0,
        label: row.1,
        points: row.2,
        max_uses: row.3,
        use_count: row.4,
        expires_at: row.5,
        disabled_at: row.6,
        created_at: row.7,
    }
}

pub async fn list(pool: &PgPool) -> Result<Vec<RedemptionCodeSummary>, crate::sqlx::Error> {
    let rows: Vec<SummaryRow> = crate::sqlx::query_as(
        "SELECT id, label, points, max_uses, use_count, expires_at, disabled_at, created_at
         FROM wallet_redemption_codes ORDER BY created_at DESC, id DESC LIMIT 500",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(summary).collect())
}

pub async fn detail(
    pool: &PgPool,
    id: i64,
) -> Result<Option<(RedemptionCodeSummary, Vec<RedemptionUse>)>, crate::sqlx::Error> {
    let Some(row): Option<SummaryRow> = crate::sqlx::query_as(
        "SELECT id, label, points, max_uses, use_count, expires_at, disabled_at, created_at
         FROM wallet_redemption_codes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let uses: Vec<(i64, String, Option<String>, i64, OffsetDateTime)> = crate::sqlx::query_as(
        "SELECT r.user_id, u.username, u.display_name, r.points, r.redeemed_at
         FROM wallet_redemptions r JOIN users u ON u.id = r.user_id
         WHERE r.code_id = $1 ORDER BY r.redeemed_at DESC, r.user_id DESC",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(Some((
        summary(row),
        uses.into_iter()
            .map(|row| RedemptionUse {
                user_id: row.0,
                username: row.1,
                display_name: row.2,
                points: row.3,
                redeemed_at: row.4,
            })
            .collect(),
    )))
}

pub async fn lock_redeemable(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &[u8],
    user_id: UserId,
) -> Result<Option<(i64, i64)>, crate::sqlx::Error> {
    crate::sqlx::query_as(
        "SELECT id, points FROM wallet_redemption_codes c
         WHERE code_digest = $1 AND disabled_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses
           AND NOT EXISTS (SELECT 1 FROM wallet_redemptions r WHERE r.code_id = c.id AND r.user_id = $2)
         FOR UPDATE")
        .bind(digest).bind(user_id).fetch_optional(&mut **transaction).await
}

pub async fn consume(
    transaction: &mut Transaction<'_, Postgres>,
    code_id: i64,
    user_id: UserId,
    points: i64,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "UPDATE wallet_redemption_codes SET use_count = use_count + 1 WHERE id = $1",
    )
    .bind(code_id)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO wallet_redemptions (code_id, user_id, points) VALUES ($1, $2, $3)",
    )
    .bind(code_id)
    .bind(user_id)
    .bind(points)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
