//! Issue #663：email-change outbox 的投递、回滚与并发语义。
//!
//! 安全告警相关的用例拆到 `email_change_outbox_alerts.rs`，共享夹具在
//! `email_change_outbox_support.rs`。

use std::sync::Arc;

use axum::http::StatusCode;
use chenxing_auth::api;

use super::email_change_outbox_support::{
    BlockingSender, CapturingSender, FailingSender, logged_in_state,
    logged_in_state_with_max_connections, start_request,
};

#[tokio::test]
async fn only_the_current_challenge_is_delivered() {
    let (state, database, key_directory, cookie, sender) =
        logged_in_state("email_change_outbox_current").await;
    let router = api::router(state.clone());

    assert_eq!(
        start_request(&router, &cookie, "first@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        start_request(&router, &cookie, "second@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("process email outbox");

    let messages = sender.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].to.to_string(), "second@example.com");
    let pending: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_email_change_challenges WHERE consumed_at IS NULL",
    )
    .fetch_one(&database)
    .await
    .expect("pending challenge count");
    assert_eq!(pending, 1);
    let pending_outbox: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_outbox
         WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL",
    )
    .fetch_one(&database)
    .await
    .expect("pending email outbox count");
    assert_eq!(pending_outbox, 0);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn challenge_and_outbox_roll_back_together_on_outbox_failure() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state("email_change_outbox_failure").await;
    let router = api::router(state);
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION fail_email_outbox_insert() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test email outbox failure'; END $$",
    )
    .execute(&database)
    .await
    .expect("create failure trigger function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER fail_email_outbox_insert
         BEFORE INSERT ON email_outbox FOR EACH ROW
         EXECUTE FUNCTION fail_email_outbox_insert()",
    )
    .execute(&database)
    .await
    .expect("create failure trigger");

    let response = start_request(&router, &cookie, "rollback@example.com").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let challenges: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_email_change_challenges")
            .fetch_one(&database)
            .await
            .expect("challenge count");
    assert_eq!(challenges, 0);
    chenxing_auth::sqlx::query("DROP TRIGGER fail_email_outbox_insert ON email_outbox")
        .execute(&database)
        .await
        .expect("drop failure trigger");
    chenxing_auth::sqlx::query("DROP FUNCTION fail_email_outbox_insert()")
        .execute(&database)
        .await
        .expect("drop failure trigger function");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn delivery_failure_keeps_the_durable_challenge_for_retry() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state("email_change_outbox_delivery").await;
    let state = state.with_email_sender(Arc::new(FailingSender));
    let router = api::router(state.clone());

    assert_eq!(
        start_request(&router, &cookie, "delivery@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let error = state.email_outbox.process_pending_outbox().await;
    assert!(error.is_ok(), "delivery errors are retried by the worker");
    let row: (i64, i64, i64, String) = chenxing_auth::sqlx::query_as(
        "SELECT
             COUNT(*) FILTER (WHERE consumed_at IS NULL),
             COUNT(*) FILTER (WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL),
             COUNT(*) FILTER (WHERE last_error IS NOT NULL),
             COALESCE(MAX(last_error), '')
         FROM user_email_change_challenges AS challenge
         JOIN email_outbox AS outbox ON outbox.challenge_id = challenge.id",
    )
    .fetch_one(&database)
    .await
    .expect("delivery retry state");
    assert_eq!(row, (1, 1, 1, "delivery_failure".to_owned()));
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn successful_delivery_with_terminal_write_failure_is_at_least_once_retryable() {
    let (state, database, key_directory, cookie, sender) =
        logged_in_state("email_change_outbox_terminal_write").await;
    let router = api::router(state.clone());
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION fail_email_outbox_processed() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN
             IF NEW.processed_at IS NOT NULL THEN
                 RAISE EXCEPTION 'test processed update failure';
             END IF;
             RETURN NEW;
         END $$",
    )
    .execute(&database)
    .await
    .expect("create processed failure function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER fail_email_outbox_processed
         BEFORE UPDATE ON email_outbox FOR EACH ROW
         EXECUTE FUNCTION fail_email_outbox_processed()",
    )
    .execute(&database)
    .await
    .expect("create processed failure trigger");

    assert_eq!(
        start_request(&router, &cookie, "terminal-write@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("failed terminal write must be scheduled for retry");

    assert_eq!(sender.messages().len(), 1);
    let row: (i64, i64, String) = chenxing_auth::sqlx::query_as(
        "SELECT
             COUNT(*) FILTER (WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL),
             COUNT(*) FILTER (WHERE last_error = 'database_failure'),
             COALESCE(MAX(last_error), '')
         FROM email_outbox",
    )
    .fetch_one(&database)
    .await
    .expect("terminal write retry state");
    assert_eq!(row, (1, 1, "database_failure".to_owned()));

    chenxing_auth::sqlx::query("DROP TRIGGER fail_email_outbox_processed ON email_outbox")
        .execute(&database)
        .await
        .expect("drop processed failure trigger");
    chenxing_auth::sqlx::query("DROP FUNCTION fail_email_outbox_processed()")
        .execute(&database)
        .await
        .expect("drop processed failure function");

    // The provider call already succeeded before the terminal write failed.
    // Owner-approved at-least-once semantics therefore permit a duplicate when
    // the retry replays the still-pending outbox row.
    chenxing_auth::sqlx::query(
        "UPDATE email_outbox
         SET available_at = NOW()
         WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL",
    )
    .execute(&database)
    .await
    .expect("make retry immediately available");
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("retry after terminal write recovery");
    assert_eq!(sender.messages().len(), 2);
    let processed: bool =
        chenxing_auth::sqlx::query_scalar("SELECT processed_at IS NOT NULL FROM email_outbox")
            .fetch_one(&database)
            .await
            .expect("processed retry state");
    assert!(processed);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_starts_leave_one_ordered_current_challenge() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state("email_change_outbox_concurrent").await;
    let router = api::router(state);
    let (first, second) = tokio::join!(
        start_request(&router, &cookie, "concurrent-a@example.com"),
        start_request(&router, &cookie, "concurrent-b@example.com"),
    );
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let row: (i64, i64) = chenxing_auth::sqlx::query_as(
        "SELECT
             COUNT(*) FILTER (WHERE consumed_at IS NULL),
             COUNT(*) FILTER (WHERE consumed_at IS NOT NULL)
         FROM user_email_change_challenges",
    )
    .fetch_one(&database)
    .await
    .expect("challenge ordering");
    assert_eq!(row, (1, 1));
    let pending_outbox: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_outbox
         WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL",
    )
    .fetch_one(&database)
    .await
    .expect("pending outbox ordering");
    assert_eq!(pending_outbox, 1);
    let cancelled_outbox: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_outbox
         WHERE cancelled_at IS NOT NULL AND processed_at IS NULL AND dead_lettered_at IS NULL",
    )
    .fetch_one(&database)
    .await
    .expect("cancelled outbox count");
    assert_eq!(cancelled_outbox, 1);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn single_connection_remains_available_during_smtp_delivery() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state_with_max_connections("email_change_outbox_send_lock", 1).await;
    let sender = BlockingSender::default().with_database(database.clone());
    let state = state.with_email_sender(Arc::new(sender.clone()));
    let router = api::router(state.clone());

    assert_eq!(
        start_request(&router, &cookie, "locked-first@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let processing = tokio::spawn({
        let outbox = state.email_outbox.clone();
        async move { outbox.process_pending_outbox().await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), sender.started.notified())
        .await
        .expect("SMTP delivery must not wait on the outbox connection");

    let second_router = router.clone();
    let second_cookie = cookie.clone();
    let second = tokio::spawn(async move {
        start_request(&second_router, &second_cookie, "locked-second@example.com").await
    });
    // Reauthentication and hashing are deliberately expensive. Keep this
    // deadline long enough for instrumented CI while the first 1s probe above
    // still detects a connection held during SMTP.
    let second_response = tokio::time::timeout(std::time::Duration::from_secs(15), second)
        .await
        .expect("a new challenge must complete while SMTP delivery is blocked")
        .expect("second request join");
    assert_eq!(second_response.status(), StatusCode::ACCEPTED);

    sender.release.notify_one();
    processing
        .await
        .expect("outbox task join")
        .expect("process email outbox");
    assert_eq!(sender.messages().len(), 1);
    assert_eq!(
        sender.messages()[0].to.to_string(),
        "locked-first@example.com"
    );
    let pending: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_outbox
         WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL",
    )
    .fetch_one(&database)
    .await
    .expect("pending second outbox");
    assert_eq!(pending, 1);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn expired_lease_reclaim_fences_stale_completion() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state("email_change_outbox_lease_fence").await;
    let blocking_sender = BlockingSender::default();
    let state = state.with_email_sender(Arc::new(blocking_sender.clone()));
    let router = api::router(state.clone());

    assert_eq!(
        start_request(&router, &cookie, "lease-fence@example.com")
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let first_processing = tokio::spawn({
        let outbox = state.email_outbox.clone();
        async move { outbox.process_pending_outbox().await }
    });
    blocking_sender.started.notified().await;
    chenxing_auth::sqlx::query(
        "UPDATE email_outbox
         SET available_at = NOW() - INTERVAL '1 second'",
    )
    .execute(&database)
    .await
    .expect("expire active lease");

    let retry_sender = CapturingSender::default();
    let retry_state = state
        .clone()
        .with_email_sender(Arc::new(retry_sender.clone()));
    retry_state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("reclaimed lease delivery");
    let row: (i32, i64, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, claim_generation, processed_at IS NOT NULL FROM email_outbox",
    )
    .fetch_one(&database)
    .await
    .expect("reclaimed lease state");
    assert_eq!(row, (2, 2, true));

    blocking_sender.release.notify_one();
    first_processing
        .await
        .expect("stale completion task join")
        .expect("stale completion is ignored");
    assert_eq!(blocking_sender.messages().len(), 1);
    assert_eq!(retry_sender.messages().len(), 1);
    let _ = std::fs::remove_dir_all(key_directory);
}
