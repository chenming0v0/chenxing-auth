use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chenxing_auth::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, RedisAuthFailureLimiter},
    users::{
        credentials::hash_password,
        domain::{LoginInput, ValidatedRegistration},
        email::EmailAddress,
        repository,
        service::UserServiceError,
    },
};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

use crate::harness::HarnessBuilder;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn limiter() -> RedisAuthFailureLimiter {
    RedisAuthFailureLimiter::new(redis::Client::open(redis_url()).expect("Redis URL"))
}

fn unique_value(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

/// 与 `auth_limiter::policy::value_hash` 同一份编码。夹具 Redis keyspace 是 legacy，
/// key 无部署前缀。哈希或前缀错了会指到一个不存在的 key。
fn dimension_key(kind: &str, dimension: FailureDimension, value: &str) -> String {
    let value_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()));
    format!("chenxing:auth:{kind}:{}:{value_hash}", dimension.as_str())
}

async fn redis_connection() -> redis::aio::MultiplexedConnection {
    redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection")
}

fn token_and_index(member: &str) -> (&str, &str) {
    member
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("failure member {member:?} must be token:index"))
}

/// 成功释放：pending 成员已被 `ZREM`，`ZCARD == 0`。
///
/// Redis 删掉 ZSET 的最后一个成员后会把 key 本身删掉，不会留下空 ZSET，所以
/// `TYPE == "none"` 是成功，不再要求空 key 的 TTL。key 还在时类型必须仍是 `zset`
/// （基数已经要求为 0）。
///
/// 错哈希也会得到 `none`，不能单靠 key 消失证明租约被释放。
/// `one_reserve_records_several_dimensions_in_one_script_call` 在调用本断言之前
/// 已经用同一份哈希确认 failure ZSET 里有成员；
/// `password_login_consumes_the_merged_account_lease` 的错密码路径随后断言
/// account/source failure 成员。真正的回归是 pending 成员还在（`ZCARD != 0`）。
async fn assert_pending_released(
    connection: &mut redis::aio::MultiplexedConnection,
    dimension: FailureDimension,
    value: &str,
) {
    let key = dimension_key("pending", dimension, value);
    let card: i64 = connection.zcard(&key).await.expect("pending zcard");
    let key_type: String = connection.key_type(&key).await.expect("pending type");
    assert_eq!(
        card, 0,
        "{key} still holds a pending member; the lease token was not ZREM'd"
    );
    if key_type != "none" {
        assert_eq!(
            key_type, "zset",
            "{key} must be the lease zset reserve() created"
        );
    }
}

async fn failure_members(
    connection: &mut redis::aio::MultiplexedConnection,
    dimension: FailureDimension,
    value: &str,
) -> Vec<String> {
    let key = dimension_key("failure", dimension, value);
    let key_type: String = connection.key_type(&key).await.expect("failure type");
    assert_eq!(key_type, "zset", "{key} must be a failure zset");
    connection
        .zrange(&key, 0, -1)
        .await
        .expect("failure members")
}

#[tokio::test]
async fn redis_reservation_script_caps_concurrent_failures_at_the_account_limit() {
    let limiter = Arc::new(limiter());
    let account = format!("integration-{}", uuid::Uuid::new_v4().simple());
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let limiter = limiter.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            let dimensions = vec![(FailureDimension::Account, account)];
            let reserved = limiter.reserve(dimensions.clone()).await.expect("reserve");
            if !reserved.is_denied() {
                limiter
                    .record_reserved_failures(reserved.clone())
                    .await
                    .expect("record reserved failure");
            }
            reserved
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        accepted += u8::from(!task.await.expect("join").is_denied());
    }
    assert_eq!(accepted, FailureDimension::Account.limit() as u8);
}

/// 空预留没有租约，不能变成一次脚本调用。`NotRecorded` 是调用方随后 release 的信号。
#[tokio::test]
async fn empty_reservation_is_not_recorded_and_release_does_not_fail() {
    let limiter = limiter();
    let reservation = limiter
        .reserve(Vec::new())
        .await
        .expect("empty reserve is a vacuous allow");
    assert!(!reservation.is_denied());
    let record = limiter
        .record_reserved_failures(reservation.clone())
        .await
        .expect("record empty reservation");
    assert!(
        !record.was_recorded(),
        "an empty reservation must stay NotRecorded so the caller releases it"
    );
    limiter
        .release(reservation)
        .await
        .expect("release empty reservation");
}

/// 一次 reserve 多维度仍是一个 token、一次脚本调用。
///
/// 失败成员是 `{token}:{脚本内下标}`。账户在前、源 IP 在后时，源 IP 必须是 `:2`
/// 且与账户共享 token。按维度拆开各调一次的话，两个成员都会是 `:1`。
#[tokio::test]
async fn one_reserve_records_several_dimensions_in_one_script_call() {
    let limiter = limiter();
    let account = unique_value("single-token-account");
    let source_ip = unique_value("single-token-ip");
    let reservation = limiter
        .reserve(vec![
            (FailureDimension::Account, account.clone()),
            (FailureDimension::SourceIp, source_ip.clone()),
        ])
        .await
        .expect("reserve account and source ip together");
    assert!(!reservation.is_denied());
    limiter
        .record_reserved_failures(reservation)
        .await
        .expect("record the single token");

    let mut connection = redis_connection().await;
    let account_members =
        failure_members(&mut connection, FailureDimension::Account, &account).await;
    let source_members =
        failure_members(&mut connection, FailureDimension::SourceIp, &source_ip).await;
    assert_eq!(account_members.len(), 1);
    assert_eq!(source_members.len(), 1);
    let (account_token, account_index) = token_and_index(&account_members[0]);
    let (source_token, source_index) = token_and_index(&source_members[0]);
    assert_eq!(account_token, source_token);
    assert_eq!(account_index, "1");
    assert_eq!(source_index, "2");
    assert_pending_released(&mut connection, FailureDimension::Account, &account).await;
    assert_pending_released(&mut connection, FailureDimension::SourceIp, &source_ip).await;
}

const PASSWORD: &str = "correct horse battery";

struct PasswordLogin {
    state: chenxing_auth::state::AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    user_id: i64,
    email: String,
    source_ip: String,
}

async fn password_login() -> PasswordLogin {
    let (state, database, key_directory, _admin_token, _binary_name) =
        HarnessBuilder::new("password_lease").build_state().await;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let email = EmailAddress::parse(&format!("lease-{suffix}@example.com")).expect("fixture email");
    let user = repository::insert_user(
        &database,
        ValidatedRegistration {
            username: format!("lease-{suffix}"),
            email: email.clone(),
            password: PASSWORD.to_owned(),
            display_name: None,
        },
        hash_password(PASSWORD.to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert user");
    PasswordLogin {
        state,
        database,
        key_directory,
        user_id: user.id,
        email: email.canonical().to_owned(),
        source_ip: format!("issue727-{suffix}"),
    }
}

async fn cleanup(login: &PasswordLogin) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(login.user_id)
        .execute(&login.database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(&login.key_directory);
}

fn login_input(identifier: &str, password: &str) -> LoginInput {
    LoginInput {
        identifier: identifier.to_owned(),
        password: password.to_owned(),
        totp_code: None,
    }
}

/// #727：口令登录先 reserve 源 IP，查到用户后再 reserve 账户，两份 token 经 merge 拼接。
///
/// 成功登录后账户 pending 成员必须被 ZREM（基数为 0；最后一条被删后 key 可以消失）。
/// 错密码后账户 failure key 必须被 ZADD，且成员下标是 `:1`——账户租约自己的那一次脚本调用。
/// 与源 IP 成员的 token 不同，说明没有把 `leases[0]` 套到两条 pending key 上。
#[tokio::test]
async fn password_login_consumes_the_merged_account_lease() {
    let login = password_login().await;

    login
        .state
        .users
        .authenticate(login_input(&login.email, PASSWORD), Some(&login.source_ip))
        .await
        .expect("correct password releases both leases");

    let mut connection = redis_connection().await;
    assert_pending_released(&mut connection, FailureDimension::Account, &login.email).await;
    assert_pending_released(
        &mut connection,
        FailureDimension::SourceIp,
        &login.source_ip,
    )
    .await;
    let account_failures_after_success: i64 = connection
        .zcard(dimension_key(
            "failure",
            FailureDimension::Account,
            &login.email,
        ))
        .await
        .expect("account failure zcard after success");
    assert_eq!(
        account_failures_after_success, 0,
        "a successful login must not ZADD an account failure"
    );

    let error = login
        .state
        .users
        .authenticate(
            login_input(&login.email, "incorrect password"),
            Some(&login.source_ip),
        )
        .await
        .expect_err("wrong password");
    assert!(
        matches!(error, UserServiceError::InvalidCredentials),
        "one wrong password must not look like a limiter outage or a lockout: {error:?}"
    );

    let account_members =
        failure_members(&mut connection, FailureDimension::Account, &login.email).await;
    let source_members = failure_members(
        &mut connection,
        FailureDimension::SourceIp,
        &login.source_ip,
    )
    .await;
    assert_eq!(
        account_members.len(),
        1,
        "wrong password must ZADD the account failure key"
    );
    assert_eq!(
        source_members.len(),
        1,
        "wrong password must also record the source IP lease"
    );
    let (account_token, account_index) = token_and_index(&account_members[0]);
    let (source_token, source_index) = token_and_index(&source_members[0]);
    assert_eq!(account_index, "1");
    assert_eq!(source_index, "1");
    assert_ne!(
        account_token, source_token,
        "account and source IP were reserved separately; one script token cannot own both"
    );
    assert_pending_released(&mut connection, FailureDimension::Account, &login.email).await;
    assert_pending_released(
        &mut connection,
        FailureDimension::SourceIp,
        &login.source_ip,
    )
    .await;

    cleanup(&login).await;
}
