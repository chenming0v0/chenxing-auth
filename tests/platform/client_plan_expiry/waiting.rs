use std::time::Duration;

use chenxing_auth::sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tokio::time::{sleep, timeout};

use super::fixtures::Fixture;

#[derive(Clone, Copy)]
pub(super) enum WaitAt {
    UserRow,
    DefaultSet,
    PlanRow,
    QuotaCount,
    IdempotencyClaim,
}

impl WaitAt {
    pub fn query_fragment(self) -> &'static str {
        match self {
            Self::UserRow => "FROM users",
            Self::DefaultSet => "pg_advisory_xact_lock",
            Self::PlanRow => "FROM plans WHERE id",
            Self::QuotaCount => "SELECT COUNT(*) FROM oauth_clients",
            Self::IdempotencyClaim => "client_operation_idempotency",
        }
    }
}

/// 在被测事务开始前设置真实到期时间；后续确认请求确实阻塞且 NOW() 仍会放行。
pub(super) async fn block_for_expiry(
    fixture: &Fixture,
    wait_at: WaitAt,
) -> (Transaction<'static, Postgres>, i32) {
    chenxing_auth::sqlx::query(
        "UPDATE users SET plan_expires_at = clock_timestamp() + INTERVAL '3 seconds'
         WHERE id = $1",
    )
    .bind(fixture.user_id)
    .execute(&fixture.env.database)
    .await
    .expect("arm plan expiry");
    let mut blocker = fixture.env.database.begin().await.expect("begin blocker");
    let pid = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("blocker backend pid");
    match wait_at {
        WaitAt::UserRow => {
            chenxing_auth::sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(fixture.user_id)
                .execute(&mut *blocker)
                .await
                .expect("lock user");
        }
        WaitAt::DefaultSet => {
            // 与 db::advisory_lock 的稳定 DefaultPlan 双 integer 键一致。
            chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock(0, 7341929)")
                .execute(&mut *blocker)
                .await
                .expect("lock default plan set");
        }
        WaitAt::PlanRow => {
            chenxing_auth::sqlx::query("SELECT id FROM plans WHERE id = $1 FOR UPDATE")
                .bind(fixture.plan_id)
                .execute(&mut *blocker)
                .await
                .expect("lock assigned plan");
        }
        WaitAt::QuotaCount => {
            chenxing_auth::sqlx::query("LOCK TABLE oauth_clients IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *blocker)
                .await
                .expect("block quota count");
        }
        WaitAt::IdempotencyClaim => {
            chenxing_auth::sqlx::query(
                "LOCK TABLE client_operation_idempotency IN ACCESS EXCLUSIVE MODE",
            )
            .execute(&mut *blocker)
            .await
            .expect("block idempotency claim");
        }
    }
    (blocker, pid)
}

pub(super) async fn wait_past_expiry(fixture: &Fixture, blocker_pid: i32, wait_at: WaitAt) {
    let transaction_start: OffsetDateTime = timeout(Duration::from_secs(15), async {
        loop {
            let started = chenxing_auth::sqlx::query_scalar(
                "SELECT xact_start FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid)) AND xact_start IS NOT NULL
                   AND query LIKE '%' || $2 || '%' LIMIT 1",
            )
            .bind(blocker_pid)
            .bind(wait_at.query_fragment())
            .fetch_optional(&fixture.env.database)
            .await
            .expect("inspect quota transaction wait");
            if let Some(started) = started {
                return started;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("creation did not reach the intended lock");
    let (now_would_accept, still_live): (bool, bool) = chenxing_auth::sqlx::query_as(
        "SELECT plan_expires_at > $2, plan_expires_at > clock_timestamp()
         FROM users WHERE id = $1",
    )
    .bind(fixture.user_id)
    .bind(transaction_start)
    .fetch_one(&fixture.env.database)
    .await
    .expect("prove frozen transaction clock fixture");
    assert!(now_would_accept, "NOW() must still accept the paid plan");
    assert!(still_live, "request must block before expiry");
    wait_until_expired(&fixture.env.database, fixture.user_id).await;
}

async fn wait_until_expired(database: &PgPool, user_id: i64) {
    timeout(Duration::from_secs(15), async {
        loop {
            let expired: bool = chenxing_auth::sqlx::query_scalar(
                "SELECT plan_expires_at <= clock_timestamp() FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_one(database)
            .await
            .expect("inspect plan expiry");
            if expired {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("plan did not expire while creation waited");
}
