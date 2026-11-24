//! #744：中断领取、实际失败和旧领取者分别验证投递失败预算。

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use chenxing_auth::{
    api,
    notifications::{EmailMessage, EmailSendError, EmailSender},
    sqlx::PgPool,
    state::AppState,
};
use tokio::sync::Notify;

#[path = "../identity/email_change_outbox_support.rs"]
mod support;
use support::{BlockingSender, CapturingSender, FailingSender, logged_in_state, start_request};

#[path = "email_outbox_failure_budget_migration.rs"]
mod migration;

async fn queued_email(name: &str) -> (AppState, PgPool, std::path::PathBuf, CapturingSender) {
    let (state, database, key_directory, cookie, sender) = logged_in_state(name).await;
    let router = api::router(state.clone());
    let response = start_request(&router, &cookie, "budget@example.com").await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    (state, database, key_directory, sender)
}

async fn make_available(database: &PgPool) {
    chenxing_auth::sqlx::query(
        "UPDATE email_outbox SET available_at = NOW()
         WHERE processed_at IS NULL AND cancelled_at IS NULL AND dead_lettered_at IS NULL",
    )
    .execute(database)
    .await
    .expect("make pending email available");
}

async fn failure_state(database: &PgPool) -> (i32, i32, bool, String) {
    chenxing_auth::sqlx::query_as(
        "SELECT attempts, failed_attempts, dead_lettered_at IS NOT NULL,
                COALESCE(last_error, '') FROM email_outbox",
    )
    .fetch_one(database)
    .await
    .expect("email failure budget state")
}

#[tokio::test]
async fn interrupted_claims_leave_the_first_recorded_failure_retryable() {
    let (state, database, key_directory, _sender) = queued_email("email_budget_interrupts").await;
    for _ in 0..12 {
        let sender = BlockingSender::default();
        let claimed = state.clone().with_email_sender(Arc::new(sender.clone()));
        let processing =
            tokio::spawn(async move { claimed.email_outbox.process_pending_outbox().await });
        tokio::time::timeout(Duration::from_secs(5), sender.started.notified())
            .await
            .expect("claimed email reached the sender");
        processing.abort();
        assert!(
            processing
                .await
                .expect_err("interrupted worker")
                .is_cancelled()
        );
        make_available(&database).await;
    }
    assert_eq!(
        failure_state(&database).await,
        (12, 0, false, String::new())
    );

    state
        .with_email_sender(Arc::new(FailingSender))
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("first recorded failure remains retryable");
    assert_eq!(
        failure_state(&database).await,
        (13, 1, false, "delivery_failure".to_owned())
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn ten_recorded_delivery_failures_reach_dead_letter_exactly_once() {
    let (state, database, key_directory, _sender) = queued_email("email_budget_failures").await;
    let state = state.with_email_sender(Arc::new(FailingSender));
    for failures in 1..=10 {
        make_available(&database).await;
        state
            .email_outbox
            .process_pending_outbox()
            .await
            .expect("record delivery failure");
        assert_eq!(
            failure_state(&database).await,
            (
                failures,
                failures,
                failures == 10,
                "delivery_failure".to_owned()
            )
        );
    }
    assert_eq!(
        state.email_outbox.process_pending_outbox().await.unwrap(),
        0
    );
    assert_eq!(failure_state(&database).await.1, 10);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[derive(Clone, Default)]
struct GatedFailureSender {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl EmailSender for GatedFailureSender {
    fn send<'a>(
        &'a self,
        _message: EmailMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), EmailSendError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.started.notify_one();
            self.release.notified().await;
            Err(EmailSendError::Delivery)
        })
    }
}

#[tokio::test]
async fn reclaimed_lease_fences_a_stale_delivery_failure_without_incrementing_budget() {
    let (state, database, key_directory, _sender) = queued_email("email_budget_stale").await;
    let sender = GatedFailureSender::default();
    let first = state.clone().with_email_sender(Arc::new(sender.clone()));
    let processing = tokio::spawn(async move { first.email_outbox.process_pending_outbox().await });
    tokio::time::timeout(Duration::from_secs(5), sender.started.notified())
        .await
        .expect("first claim reached SMTP");
    make_available(&database).await;
    state
        .with_email_sender(Arc::new(FailingSender))
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("new claim records the failure");
    chenxing_auth::sqlx::query("UPDATE email_outbox SET available_at = NOW() + INTERVAL '1 hour'")
        .execute(&database)
        .await
        .expect("keep the current retry outside the stale worker pass");

    sender.release.notify_one();
    processing
        .await
        .expect("stale failure task")
        .expect("stale failure is ignored");
    assert_eq!(
        failure_state(&database).await,
        (2, 1, false, "delivery_failure".to_owned())
    );
    let unchanged: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT available_at > NOW() + INTERVAL '59 minutes' FROM email_outbox",
    )
    .fetch_one(&database)
    .await
    .expect("current retry schedule");
    assert!(unchanged);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn smtp_success_with_uncertain_terminal_write_does_not_spend_the_last_failure() {
    let (state, database, key_directory, sender) = queued_email("email_budget_uncertain").await;
    chenxing_auth::sqlx::query("UPDATE email_outbox SET failed_attempts = 9")
        .execute(&database)
        .await
        .expect("reserve the final delivery failure");
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION fail_email_budget_processed() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN
             IF NEW.processed_at IS NOT NULL THEN
                 RAISE EXCEPTION 'test terminal write failure';
             END IF;
             RETURN NEW;
         END $$",
    )
    .execute(&database)
    .await
    .expect("terminal failure function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER fail_email_budget_processed BEFORE UPDATE ON email_outbox
         FOR EACH ROW EXECUTE FUNCTION fail_email_budget_processed()",
    )
    .execute(&database)
    .await
    .expect("terminal failure trigger");

    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("uncertain terminal state stays retryable");
    assert_eq!(sender.messages().len(), 1);
    assert_eq!(
        failure_state(&database).await,
        (1, 9, false, "database_failure".to_owned())
    );

    chenxing_auth::sqlx::query("DROP TRIGGER fail_email_budget_processed ON email_outbox")
        .execute(&database)
        .await
        .expect("recover terminal writes");
    chenxing_auth::sqlx::query("DROP FUNCTION fail_email_budget_processed()")
        .execute(&database)
        .await
        .expect("remove terminal failure function");
    make_available(&database).await;
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("at-least-once retry after recovery");
    assert_eq!(sender.messages().len(), 2);
    let row: (i32, bool, bool) = chenxing_auth::sqlx::query_as(
        "SELECT failed_attempts, processed_at IS NOT NULL, dead_lettered_at IS NOT NULL
         FROM email_outbox",
    )
    .fetch_one(&database)
    .await
    .expect("settled delivery state");
    assert_eq!(row, (9, true, false));
    let _ = std::fs::remove_dir_all(key_directory);
}
