//! Issue #275：session outbox 的有界生命周期。
//!
//! 覆盖三条独立的失效路径，它们共同决定这张表是否有界：
//!
//! 1. 终态事件按保留窗口被有界批量清理，正在重试的事件不受影响。
//! 2. 0 行撤销不产生投递任务（重复登出、对不存在令牌登出）。
//! 3. 永久失败在尝试预算耗尽后进入 dead-letter，不再被领取。
//!
//! 单独一个测试二进制而不是塞进 `integration_storage`：那个文件已经 2200 行，
//! 而这里的夹具（收紧的保留窗口和尝试预算）与它的任何用例都不共享。

use crate::db_isolation;

use std::{env, time::Duration};

use chenxing_auth::{
    sessions::{
        SessionOutboxPolicy,
        domain::{Session, session_token_hash_bytes},
        store::SessionStore,
    },
    users::{domain::ValidatedRegistration, email::EmailAddress, repository as user_repository},
};
use time::OffsetDateTime;
use uuid::Uuid;

/// 测试夹具的邮箱构造。
///
/// `ValidatedRegistration.email` 是 `EmailAddress`（Issue #302），构造它必须经过
/// 唯一的规范化入口——夹具也不例外，否则测试会绕开被测的那条规则。
fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

const STORE_KEY: [u8; 32] = [0x75; 32];
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("session_outbox_retention", &database_url).await
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

/// 指向一个已保留但未监听的端口，制造稳定可复现的投递失败。
fn unavailable_redis_client() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL")
}

async fn insert_user(pool: &chenxing_auth::sqlx::PgPool, prefix: &str) -> i64 {
    let suffix = Uuid::new_v4().simple().to_string();
    user_repository::insert_user(
        pool,
        ValidatedRegistration {
            username: format!("{prefix}-{suffix}"),
            email: email_address(format!("{prefix}-{suffix}@example.com")),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox retention user")
    .id
}

/// outbox 行的终态类别。
#[derive(Clone, Copy)]
enum Terminal {
    Processed,
    DeadLettered,
}

/// 直接写入一条处于指定终态、指定年龄的 outbox 行。
///
/// 用 SQL 夹具而不是驱动真实流程：保留窗口以天计，真实流程无法产出"三天前处理完"
/// 的行，而这里要验证的正是窗口边界。
///
/// 两个终态列都出现在同一条语句里，未使用的那个绑定为 `NULL`：语句因此是固定的，
/// 不需要把列名拼进 SQL。CHECK 约束也顺带被覆盖——两列不可能同时非空。
async fn insert_settled_event(
    pool: &chenxing_auth::sqlx::PgPool,
    terminal: Terminal,
    age: Duration,
) -> i64 {
    let settled_at = OffsetDateTime::now_utc() - time::Duration::try_from(age).expect("event age");
    let (processed_at, dead_lettered_at) = match terminal {
        Terminal::Processed => (Some(settled_at), None),
        Terminal::DeadLettered => (None, Some(settled_at)),
    };
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO session_outbox
             (operation, token_hash, attempts, processed_at, dead_lettered_at)
         VALUES ('revoke_session', $1, 1, $2, $3)
         RETURNING id",
    )
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(processed_at)
    .bind(dead_lettered_at)
    .fetch_one(pool)
    .await
    .expect("insert settled outbox event")
}

async fn count_revoke_events(pool: &chenxing_auth::sqlx::PgPool, token_hash: &[u8]) -> i64 {
    chenxing_auth::sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM session_outbox
         WHERE operation = 'revoke_session' AND token_hash = $1",
    )
    .bind(token_hash.to_vec())
    .fetch_one(pool)
    .await
    .expect("count revoke outbox events")
}

async fn event_exists(pool: &chenxing_auth::sqlx::PgPool, id: i64) -> bool {
    chenxing_auth::sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM session_outbox WHERE id = $1)",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("check outbox event existence")
}

/// 终态事件在保留窗口外被删除，窗口内和待处理的行保持原样，且单次清理有界。
#[tokio::test]
async fn settled_outbox_events_are_pruned_in_bounded_batches_after_their_retention_window() {
    let pool = database().await;
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY)
        .with_outbox_policy(SessionOutboxPolicy {
            processed_retention: ONE_DAY,
            dead_letter_retention: 7 * ONE_DAY,
            // 批量设成 2，配上每类 3 条过期行，让"有界"变成可观察的：一次清理
            // 删不完，必须多轮才收敛。批量若无效，第一轮就会把 6 条全删掉。
            cleanup_batch: 2,
            ..SessionOutboxPolicy::default()
        });

    let mut expired_processed = Vec::new();
    let mut expired_dead_letters = Vec::new();
    for _ in 0..3 {
        expired_processed.push(insert_settled_event(&pool, Terminal::Processed, 3 * ONE_DAY).await);
        expired_dead_letters
            .push(insert_settled_event(&pool, Terminal::DeadLettered, 30 * ONE_DAY).await);
    }
    let fresh_processed =
        insert_settled_event(&pool, Terminal::Processed, Duration::from_secs(3_600)).await;
    let fresh_dead_letter = insert_settled_event(&pool, Terminal::DeadLettered, ONE_DAY).await;

    // 待处理行是清理绝对不能碰的：删掉一条待投递的撤销事件就等于永久丢失一次
    // Redis 投影撤销。用一个远期 available_at 保证它在整个测试期间保持待处理。
    let pending: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO session_outbox (operation, token_hash, available_at)
         VALUES ('revoke_session', $1, NOW() + INTERVAL '1 hour')
         RETURNING id",
    )
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .expect("insert pending outbox event");

    let first = store
        .prune_settled_outbox()
        .await
        .expect("first retention batch");
    assert_eq!(
        first.processed, 2,
        "processed cleanup must respect the batch"
    );
    assert_eq!(
        first.dead_lettered, 2,
        "dead-letter cleanup must respect the batch"
    );
    assert!(
        first.is_saturated(2),
        "a full batch must report saturation so the worker keeps draining"
    );

    let second = store
        .prune_settled_outbox()
        .await
        .expect("second retention batch");
    assert_eq!(second.processed, 1);
    assert_eq!(second.dead_lettered, 1);
    assert!(!second.is_saturated(2), "the backlog must be drained now");

    let third = store
        .prune_settled_outbox()
        .await
        .expect("third retention batch");
    assert_eq!(
        third.total(),
        0,
        "cleanup must stop once nothing is outside the retention window"
    );

    for id in expired_processed.iter().chain(expired_dead_letters.iter()) {
        assert!(
            !event_exists(&pool, *id).await,
            "expired settled event {id} must be removed"
        );
    }
    assert!(
        event_exists(&pool, fresh_processed).await,
        "a processed event inside its retention window must be kept"
    );
    assert!(
        event_exists(&pool, fresh_dead_letter).await,
        "a dead-lettered event inside its retention window must be kept"
    );
    assert!(
        event_exists(&pool, pending).await,
        "cleanup must never remove a pending event"
    );
}

/// 重复撤销和撤销不存在的令牌都不写 outbox。
///
/// 只有"未撤销 -> 已撤销"的状态转变才有需要删除的 Redis 投影。第二次调用没有
/// 投影要删，事件必然空转成功，纯粹是表增长。
#[tokio::test]
async fn a_revoke_that_changes_no_row_does_not_enqueue_a_projection_event() {
    let pool = database().await;
    let user_id = insert_user(&pool, "outbox-dup-revoke").await;
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    store
        .process_pending_outbox()
        .await
        .expect("flush the save outbox");

    let token_hash = session_token_hash_bytes(&session.token).to_vec();
    assert_eq!(count_revoke_events(&pool, &token_hash).await, 0);

    store.revoke(&session.token).await.expect("first revoke");
    assert_eq!(
        count_revoke_events(&pool, &token_hash).await,
        1,
        "the state transition must enqueue exactly one projection event"
    );
    let first_revoked_at: OffsetDateTime =
        chenxing_auth::sqlx::query_scalar("SELECT revoked_at FROM user_sessions WHERE id = $1")
            .bind(session.id)
            .fetch_one(&pool)
            .await
            .expect("read first revocation time");

    for _ in 0..3 {
        store
            .revoke(&session.token)
            .await
            .expect("repeated revoke must stay successful");
    }
    assert_eq!(
        count_revoke_events(&pool, &token_hash).await,
        1,
        "repeated revocation must not enqueue further projection events"
    );
    let stable_revoked_at: OffsetDateTime =
        chenxing_auth::sqlx::query_scalar("SELECT revoked_at FROM user_sessions WHERE id = $1")
            .bind(session.id)
            .fetch_one(&pool)
            .await
            .expect("read revocation time after repeats");
    assert_eq!(
        stable_revoked_at, first_revoked_at,
        "repeated revocation must not move the audited revocation time"
    );

    let unknown =
        Session::new(user_id.to_string(), Duration::from_secs(60)).expect("unknown token");
    store
        .revoke(&unknown.token)
        .await
        .expect("revoking an unknown token must stay successful");
    assert_eq!(
        count_revoke_events(&pool, &session_token_hash_bytes(&unknown.token)).await,
        0,
        "revoking a token with no session row must not enqueue an event"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup duplicate revoke user");
}

/// 投递预算耗尽后进入 dead-letter，不再被领取，并按更长的窗口清理。
#[tokio::test]
async fn permanently_failing_delivery_stops_retrying_and_becomes_auditable() {
    let pool = database().await;
    let user_id = insert_user(&pool, "outbox-dead-letter").await;
    let max_attempts = 3;
    let store =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), STORE_KEY)
            .with_outbox_policy(SessionOutboxPolicy {
                max_attempts,
                dead_letter_retention: 7 * ONE_DAY,
                ..SessionOutboxPolicy::default()
            });
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("database save must not depend on Redis availability");

    let outbox_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(session.id)
    .fetch_one(&pool)
    .await
    .expect("locate the pending sync event");

    // 循环条件按观察到的状态推进，不按轮次计数：一次 process_pending_outbox 内部
    // 可能连续领取同一行（退避到期后 while 循环会再次领取），断言因此写成不变式
    // "dead-letter 当且仅当尝试次数达到预算"，与调度时序无关。
    let mut dead_lettered = false;
    for _ in 0..(max_attempts * 4) {
        assert_eq!(
            store
                .process_pending_outbox()
                .await
                .expect("record a failed delivery"),
            0,
            "delivery to an unavailable Redis must not report success"
        );
        let (attempts, is_dead_lettered): (i32, bool) = chenxing_auth::sqlx::query_as(
            "SELECT attempts, dead_lettered_at IS NOT NULL
             FROM session_outbox WHERE id = $1",
        )
        .bind(outbox_id)
        .fetch_one(&pool)
        .await
        .expect("observe the failing event");
        assert!(
            attempts <= max_attempts,
            "attempts must never exceed the budget"
        );
        assert_eq!(
            is_dead_lettered,
            attempts >= max_attempts,
            "dead-letter must happen exactly when the attempt budget is exhausted, \
             observed attempts={attempts}"
        );
        if is_dead_lettered {
            dead_lettered = true;
            break;
        }
        // 退避把 available_at 推到未来。这里只压缩时间，不改变尝试计数语义。
        chenxing_auth::sqlx::query("UPDATE session_outbox SET available_at = NOW() WHERE id = $1")
            .bind(outbox_id)
            .execute(&pool)
            .await
            .expect("make the failing event immediately retryable");
    }
    assert!(
        dead_lettered,
        "a permanently failing event must reach the dead-letter state"
    );

    let (attempts, has_error, processed): (i32, bool, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, last_error IS NOT NULL, processed_at IS NOT NULL
         FROM session_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read the dead-lettered event");
    assert_eq!(attempts, max_attempts);
    assert!(
        has_error,
        "a dead-lettered event must retain its last error"
    );
    assert!(!processed, "a dead-lettered event must not look processed");

    // 关键断言：预算耗尽后不再重试。原来的行为是每 5 分钟重新领取一次，直到部署寿命结束。
    chenxing_auth::sqlx::query("UPDATE session_outbox SET available_at = NOW() WHERE id = $1")
        .bind(outbox_id)
        .execute(&pool)
        .await
        .expect("make the dead-lettered event nominally available");
    store
        .process_pending_outbox()
        .await
        .expect("process with a dead-lettered event present");
    let attempts_after: i32 =
        chenxing_auth::sqlx::query_scalar("SELECT attempts FROM session_outbox WHERE id = $1")
            .bind(outbox_id)
            .fetch_one(&pool)
            .await
            .expect("read attempts after the dead letter");
    assert_eq!(
        attempts_after, max_attempts,
        "a dead-lettered event must never be claimed again"
    );

    // dead-letter 行仍然是有界的：它按自己的（更长的）窗口被清理。
    assert_eq!(
        store
            .prune_settled_outbox()
            .await
            .expect("cleanup inside the dead-letter window")
            .dead_lettered,
        0,
        "a fresh dead letter must survive its retention window"
    );
    chenxing_auth::sqlx::query(
        "UPDATE session_outbox SET dead_lettered_at = NOW() - INTERVAL '30 days' WHERE id = $1",
    )
    .bind(outbox_id)
    .execute(&pool)
    .await
    .expect("age the dead-lettered event past its window");
    assert_eq!(
        store
            .prune_settled_outbox()
            .await
            .expect("cleanup outside the dead-letter window")
            .dead_lettered,
        1
    );
    assert!(
        !event_exists(&pool, outbox_id).await,
        "an expired dead letter must be removed"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup dead letter user");
}
