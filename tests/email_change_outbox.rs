use std::sync::{Arc, Mutex};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    notifications::{EmailMessage, EmailSender},
    sqlx::PgPool,
    state::AppState,
};
use tokio::sync::Notify;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const PASSWORD: &str = "correct horse battery";

fn csrf_token(cookie: &str) -> &str {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
}

#[derive(Clone, Default)]
struct CapturingSender {
    messages: Arc<Mutex<Vec<EmailMessage>>>,
}

#[derive(Clone, Default)]
struct FailingSender;

impl EmailSender for FailingSender {
    fn send<'a>(
        &'a self,
        _message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(chenxing_auth::notifications::EmailSendError::Delivery) })
    }
}

impl CapturingSender {
    fn messages(&self) -> Vec<EmailMessage> {
        self.messages.lock().expect("sender lock").clone()
    }
}

impl EmailSender for CapturingSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        let messages = self.messages.clone();
        Box::pin(async move {
            messages.lock().expect("sender lock").push(message);
            Ok(())
        })
    }
}

#[derive(Clone, Default)]
struct BlockingSender {
    messages: Arc<Mutex<Vec<EmailMessage>>>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    first_send: Arc<Mutex<bool>>,
}

impl BlockingSender {
    fn messages(&self) -> Vec<EmailMessage> {
        self.messages.lock().expect("sender lock").clone()
    }
}

impl EmailSender for BlockingSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        let messages = self.messages.clone();
        let started = self.started.clone();
        let release = self.release.clone();
        let should_block = {
            let mut first_send = self.first_send.lock().expect("sender lock");
            if *first_send {
                false
            } else {
                *first_send = true;
                true
            }
        };
        Box::pin(async move {
            if should_block {
                started.notify_one();
                release.notified().await;
                messages.lock().expect("sender lock").push(message);
                Ok(())
            } else {
                Err(chenxing_auth::notifications::EmailSendError::Delivery)
            }
        })
    }
}

async fn start_request(
    router: &axum::Router,
    cookie: &str,
    email: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/email-change/start")
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_token(cookie))
                .body(Body::from(
                    serde_json::json!({
                        "new_email": email,
                        "current_password": PASSWORD,
                    })
                    .to_string(),
                ))
                .expect("email change request"),
        )
        .await
        .expect("email change response")
}

async fn start_challenge(router: &axum::Router, cookie: &str, email: &str) -> Uuid {
    let response = start_request(router, cookie, email).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("email change response body");
    serde_json::from_slice::<serde_json::Value>(&body)
        .expect("email change response json")["challenge_id"]
        .as_str()
        .expect("challenge id")
        .parse()
        .expect("uuid challenge id")
}

fn verification_code(messages: &[EmailMessage]) -> String {
    messages
        .iter()
        .find(|message| message.subject == "辰星通行证邮箱变更验证码")
        .and_then(|message| message.body.split('：').nth(1))
        .and_then(|code| code.split('\n').next())
        .map(str::to_owned)
        .expect("verification code message")
}

async fn logged_in_state(
    binary_name: &str,
) -> (
    AppState,
    PgPool,
    std::path::PathBuf,
    String,
    CapturingSender,
) {
    let (state, database, key_directory) =
        oauth_flow::test_state_with_max_connections(binary_name, 4).await;
    let sender = CapturingSender::default();
    let state = state.with_email_sender(Arc::new(sender.clone()));
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, &database, binary_name, "email-change-owner")
        .await;
    let (_user_id, username, _email, _password) =
        oauth_flow::register_test_user(&router, "email-change-user").await;
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": username, "password": PASSWORD}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = oauth_flow::cookie_header(&login);
    (state, database, key_directory, cookie, sender)
}

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
async fn successful_delivery_with_terminal_write_failure_remains_retryable() {
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
async fn new_challenge_waits_for_in_flight_delivery() {
    let (state, database, key_directory, cookie, _sender) =
        logged_in_state("email_change_outbox_send_lock").await;
    let sender = BlockingSender::default();
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
    sender.started.notified().await;

    let second_router = router.clone();
    let second_cookie = cookie.clone();
    let mut second = tokio::spawn(async move {
        start_request(&second_router, &second_cookie, "locked-second@example.com").await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut second)
            .await
            .is_err(),
        "a new challenge must wait while the old delivery owns the user lock"
    );

    sender.release.notify_one();
    processing
        .await
        .expect("outbox task join")
        .expect("process email outbox");
    assert_eq!(
        second.await.expect("second request join").status(),
        StatusCode::ACCEPTED
    );
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
