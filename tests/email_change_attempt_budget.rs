//! Issue #663: email-change code verification must have an atomic, bounded
//! failure budget even when requests arrive concurrently.

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

use std::sync::{Arc, Mutex};

use chenxing_auth::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, domain::LimiterFuture},
    config::{AuthEncryptionKey, AuthEncryptionKeyRing, Config},
    notifications::{EmailMessage, EmailSendError, EmailSender},
    state::AppState,
    users::{
        credentials::hash_password, domain::ValidatedRegistration, email::EmailAddress, repository,
        service::UserService,
    },
};
use time::OffsetDateTime;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery";

fn test_email_encryption_keys() -> AuthEncryptionKeyRing {
    AuthEncryptionKeyRing::single(AuthEncryptionKey::new([0_u8; 32]))
}

#[derive(Default)]
struct AllowingLimiter;

impl AuthFailureLimiter for AllowingLimiter {
    fn is_limited<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn record_failure<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn clear<'a>(&'a self, _dimension: FailureDimension, _value: &str) -> LimiterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct CapturingSender {
    code: Mutex<Option<String>>,
}

impl CapturingSender {
    fn code(&self) -> String {
        self.code
            .lock()
            .expect("sender lock")
            .clone()
            .expect("verification code")
    }
}

impl EmailSender for CapturingSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), EmailSendError>> + Send + 'a>>
    {
        let code = message
            .body
            .lines()
            .next()
            .expect("code line")
            .chars()
            .rev()
            .take(6)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        *self.code.lock().expect("sender lock") = Some(code);
        Box::pin(async { Ok(()) })
    }
}

async fn setup() -> (
    AppState,
    chenxing_auth::sqlx::PgPool,
    i64,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool_with_max_connections(
        "email_change_attempt_budget",
        &database_url,
        16,
    )
    .await;
    let key_directory = key_directory::isolated_key_directory("email-change-attempt-budget");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test config");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let email_encryption_keys = test_email_encryption_keys();
    config.auth_encryption_keys = email_encryption_keys.clone();
    let sender = Arc::new(CapturingSender::default());
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state")
        .with_email_sender(sender);
    state.users = state
        .users
        .clone()
        .with_email_encryption_keys(email_encryption_keys);
    let suffix = Uuid::new_v4().simple().to_string();
    let email_text = format!("email-change-{suffix}@example.com");
    let email = EmailAddress::parse(&email_text).expect("fixture email");
    let user = repository::insert_user(
        &database,
        ValidatedRegistration {
            username: format!("email-change-{suffix}"),
            email,
            password: PASSWORD.to_owned(),
            display_name: None,
        },
        hash_password(PASSWORD.to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert user");
    (state, database, user.id, key_directory)
}

async fn start(
    users: &UserService,
    outbox: &chenxing_auth::notifications::EmailOutbox,
    sender: Arc<CapturingSender>,
    user_id: i64,
) -> (Uuid, String) {
    let source_ip = format!("test-source-{}", Uuid::new_v4().simple());
    let start = users
        .start_email_change(
            user_id,
            &format!("replacement-{}@example.com", Uuid::new_v4().simple()),
            PASSWORD,
            Some(source_ip.as_str()),
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("start email change");
    outbox
        .process_pending_outbox()
        .await
        .expect("deliver email change code");
    (start.challenge_id, sender.code())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_wrong_codes_stop_at_the_atomic_threshold() {
    let (state, database, user_id, key_directory) = setup().await;
    let sender = Arc::new(CapturingSender::default());
    let state = state.with_email_sender(sender.clone());
    let (challenge_id, code) = start(&state.users, &state.email_outbox, sender, user_id).await;
    let wrong_code = if code != "000000" { "000000" } else { "999999" };
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let users = state.users.clone();
        tasks.push(tokio::spawn(async move {
            users
                .confirm_email_change(user_id, challenge_id, wrong_code)
                .await
        }));
    }
    for task in tasks {
        let _ = task.await.expect("confirmation task");
    }

    let row: (i64, i64, Option<OffsetDateTime>) = chenxing_auth::sqlx::query_as(
        "SELECT failed_attempts, in_flight_attempts, consumed_at
         FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge state");
    assert_eq!(row.0, 5);
    assert_eq!(row.1, 0);
    assert!(row.2.is_some(), "threshold must invalidate the challenge");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn challenge_attempts_are_bound_to_the_authenticated_user() {
    let (state, database, user_id, key_directory) = setup().await;
    let sender = Arc::new(CapturingSender::default());
    let state = state.with_email_sender(sender.clone());
    let (challenge_id, code) = start(&state.users, &state.email_outbox, sender, user_id).await;
    let other_user_id = user_id + 1;

    let other_user = state
        .users
        .confirm_email_change(other_user_id, challenge_id, &code)
        .await;
    assert!(matches!(
        other_user,
        Err(chenxing_auth::users::service::EmailChangeError::InvalidChallenge)
    ));

    let result = state
        .users
        .confirm_email_change(user_id, challenge_id, &code)
        .await;
    assert!(result.is_ok(), "the owning user must retain the challenge");

    let row: (i64, i64) = chenxing_auth::sqlx::query_as(
        "SELECT failed_attempts, in_flight_attempts
         FROM user_email_change_challenges WHERE id = $1 AND user_id = $2",
    )
    .bind(challenge_id)
    .bind(user_id)
    .fetch_one(&database)
    .await
    .expect("challenge state");
    assert_eq!(row, (0, 0));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn fifth_wrong_code_invalidates_the_challenge_and_later_attempts_are_invalid() {
    let (state, database, user_id, key_directory) = setup().await;
    let sender = Arc::new(CapturingSender::default());
    let state = state.with_email_sender(sender.clone());
    let (challenge_id, code) = start(&state.users, &state.email_outbox, sender, user_id).await;
    let wrong_code = if code != "000000" { "000000" } else { "999999" };

    for attempt in 0..5 {
        let result = state
            .users
            .confirm_email_change(user_id, challenge_id, wrong_code)
            .await;
        if attempt < 4 {
            assert!(matches!(
                result,
                Err(chenxing_auth::users::service::EmailChangeError::InvalidCode)
            ));
        } else {
            assert!(matches!(
                result,
                Err(chenxing_auth::users::service::EmailChangeError::RateLimited)
            ));
        }
    }

    let after_threshold = state
        .users
        .confirm_email_change(user_id, challenge_id, &code)
        .await;
    assert!(matches!(
        after_threshold,
        Err(chenxing_auth::users::service::EmailChangeError::InvalidChallenge)
    ));

    let row: (i64, i64, bool) = chenxing_auth::sqlx::query_as(
        "SELECT failed_attempts, in_flight_attempts, consumed_at IS NOT NULL
         FROM user_email_change_challenges WHERE id = $1 AND user_id = $2",
    )
    .bind(challenge_id)
    .bind(user_id)
    .fetch_one(&database)
    .await
    .expect("challenge state");
    assert_eq!(row, (5, 0, true));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn correct_code_wins_a_race_with_wrong_codes_without_resurrection() {
    let (state, database, user_id, key_directory) = setup().await;
    let sender = Arc::new(CapturingSender::default());
    let state = state.with_email_sender(sender.clone());
    let (challenge_id, code) = start(&state.users, &state.email_outbox, sender, user_id).await;
    let wrong_code = if code != "000000" { "000000" } else { "999999" };
    let barrier = Arc::new(tokio::sync::Barrier::new(5));
    let mut tasks = Vec::new();

    for _ in 0..4 {
        let users = state.users.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            users
                .confirm_email_change(user_id, challenge_id, wrong_code)
                .await
        }));
    }
    {
        let users = state.users.clone();
        let code = code.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            users
                .confirm_email_change(user_id, challenge_id, &code)
                .await
        }));
    }

    let mut successes = 0;
    for task in tasks {
        if task.await.expect("confirmation task").is_ok() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);

    let state: (bool, i64) = chenxing_auth::sqlx::query_as(
        "SELECT consumed_at IS NOT NULL, in_flight_attempts
         FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge state");
    assert!(state.0);
    assert_eq!(state.1, 0, "every concurrent verification slot must drain");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_losers_return_only_expected_client_errors() {
    let (state, database, user_id, key_directory) = setup().await;
    let sender = Arc::new(CapturingSender::default());
    let state = state.with_email_sender(sender.clone());
    let users = UserService::new(database.clone(), Arc::new(AllowingLimiter))
        .with_email_encryption_keys(test_email_encryption_keys());
    let (challenge_id, code) = start(&users, &state.email_outbox, sender, user_id).await;
    let wrong_code = if code != "000000" { "000000" } else { "999999" };
    let barrier = Arc::new(tokio::sync::Barrier::new(6));
    let mut tasks = Vec::new();

    for _ in 0..5 {
        let users = users.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            users
                .confirm_email_change(user_id, challenge_id, wrong_code)
                .await
        }));
    }
    {
        let users = users.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            users
                .confirm_email_change(user_id, challenge_id, &code)
                .await
        }));
    }

    let mut successes = 0;
    for task in tasks {
        match task.await.expect("confirmation task") {
            Ok(_) => successes += 1,
            Err(
                chenxing_auth::users::service::EmailChangeError::InvalidCode
                | chenxing_auth::users::service::EmailChangeError::InvalidChallenge
                | chenxing_auth::users::service::EmailChangeError::RateLimited,
            ) => {}
            Err(error) => panic!("concurrent confirmation leaked server error: {error}"),
        }
    }
    assert!(successes <= 1);

    let row: (i64, i64, bool) = chenxing_auth::sqlx::query_as(
        "SELECT failed_attempts, in_flight_attempts, consumed_at IS NOT NULL
         FROM user_email_change_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&database)
    .await
    .expect("challenge state");
    assert_eq!(row.1, 0, "every concurrent verification slot must drain");
    assert!(row.0 <= 5);
    assert!(row.2);

    let _ = std::fs::remove_dir_all(key_directory);
}
