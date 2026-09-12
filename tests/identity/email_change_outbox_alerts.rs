//! Issue #663：邮箱变更安全告警的持久化与 SMTP 失败重试语义。
//!
//! 与 `email_change_outbox.rs` 共享 `email_change_outbox_support.rs` 中的夹具。

use std::sync::Arc;

use chenxing_auth::api;

use super::email_change_outbox_support::{
    CapturingSender, FailingSender, logged_in_state, start_challenge, verification_code,
};

#[tokio::test]
async fn email_change_commits_a_durable_security_alert_without_plaintext_code() {
    let (state, database, key_directory, cookie, sender) =
        logged_in_state("email_change_security_alert").await;
    let router = api::router(state.clone());
    let challenge_id = start_challenge(&router, &cookie, "alert-target@example.com").await;
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("deliver verification code");
    let code = verification_code(&sender.messages());
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT user_id FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge user");
    let old_email: String =
        chenxing_auth::sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&database)
            .await
            .expect("old email");

    state
        .users
        .confirm_email_change(user_id, challenge_id, &code)
        .await
        .expect("confirm email change");

    let alert: (String, String, bool, bool) = chenxing_auth::sqlx::query_as(
        "SELECT kind, recipient, encrypted_code IS NULL,
                processed_at IS NULL
         FROM email_outbox
         WHERE challenge_id = $1 AND kind = 'email_change_security_alert'",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("durable security alert");
    assert_eq!(
        alert,
        (
            "email_change_security_alert".to_owned(),
            old_email,
            true,
            true
        )
    );

    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("deliver security alert");
    let messages = sender.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].subject, "辰星通行证邮箱已变更");
    assert_eq!(messages[1].to.to_string(), alert.1);
    assert!(!messages[1].body.contains(&code));
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("settled outbox is idempotent");
    assert_eq!(sender.messages().len(), 2);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn security_alert_insert_failure_rolls_back_email_change() {
    let (state, database, key_directory, cookie, sender) =
        logged_in_state("email_change_security_alert_rollback").await;
    let router = api::router(state.clone());
    let challenge_id = start_challenge(&router, &cookie, "alert-rollback@example.com").await;
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("deliver verification code");
    let code = verification_code(&sender.messages());
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT user_id FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge user");
    let old_email: String =
        chenxing_auth::sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&database)
            .await
            .expect("old email");
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION fail_email_security_alert_insert() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.kind = 'email_change_security_alert' THEN
                 RAISE EXCEPTION 'test security alert outbox failure';
             END IF;
             RETURN NEW;
         END
         $$",
    )
    .execute(&database)
    .await
    .expect("create security alert failure function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER fail_email_security_alert_insert
         BEFORE INSERT ON email_outbox FOR EACH ROW
         EXECUTE FUNCTION fail_email_security_alert_insert()",
    )
    .execute(&database)
    .await
    .expect("create security alert failure trigger");

    assert!(
        state
            .users
            .confirm_email_change(user_id, challenge_id, &code)
            .await
            .is_err()
    );
    let current_email: String =
        chenxing_auth::sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&database)
            .await
            .expect("current email after rollback");
    let consumed: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge state after rollback");
    let alerts: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_outbox
         WHERE challenge_id = $1 AND kind = 'email_change_security_alert'",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("security alert count after rollback");
    assert_eq!(current_email, old_email);
    assert!(!consumed);
    assert_eq!(alerts, 0);

    chenxing_auth::sqlx::query("DROP TRIGGER fail_email_security_alert_insert ON email_outbox")
        .execute(&database)
        .await
        .expect("drop security alert failure trigger");
    chenxing_auth::sqlx::query("DROP FUNCTION fail_email_security_alert_insert()")
        .execute(&database)
        .await
        .expect("drop security alert failure function");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn security_alert_survives_smtp_failure_and_outbox_restart() {
    let (state, database, key_directory, cookie, sender) =
        logged_in_state("email_change_security_alert_retry").await;
    let router = api::router(state.clone());
    let challenge_id = start_challenge(&router, &cookie, "alert-retry@example.com").await;
    state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("deliver verification code");
    let code = verification_code(&sender.messages());
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT user_id FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge user");
    state
        .users
        .confirm_email_change(user_id, challenge_id, &code)
        .await
        .expect("confirm email change");

    let failing_state = state.with_email_sender(Arc::new(FailingSender));
    failing_state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("SMTP failure is retryable");
    let failure: (i32, String) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, COALESCE(last_error, '') FROM email_outbox
         WHERE challenge_id = $1 AND kind = 'email_change_security_alert'",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("security alert retry state");
    assert_eq!(failure, (1, "delivery_failure".to_owned()));

    chenxing_auth::sqlx::query(
        "UPDATE email_outbox SET available_at = NOW()
         WHERE challenge_id = $1 AND kind = 'email_change_security_alert'",
    )
    .bind(challenge_id)
    .execute(&database)
    .await
    .expect("make security alert retryable");
    let retry_sender = CapturingSender::default();
    let restarted_state = failing_state.with_email_sender(Arc::new(retry_sender.clone()));
    restarted_state
        .email_outbox
        .process_pending_outbox()
        .await
        .expect("restarted outbox delivers alert");
    assert_eq!(retry_sender.messages().len(), 1);
    assert_eq!(retry_sender.messages()[0].subject, "辰星通行证邮箱已变更");
    let processed: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT processed_at IS NOT NULL FROM email_outbox
         WHERE challenge_id = $1 AND kind = 'email_change_security_alert'",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("processed security alert");
    assert!(processed);
    let _ = std::fs::remove_dir_all(key_directory);
}
