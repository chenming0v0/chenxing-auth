//! Issue #274：认证结果必须绑定读取凭据时的 `session_epoch`。
//!
//! 漏洞形态：登录请求先读出旧 `password_hash` 并校验通过，与此同时改密事务提交，
//! 把 `session_epoch + 1` 并撤销全部会话。旧实现在签发凭据时**重新读**当前 epoch，
//! 于是刚被作废的口令仍能换出一张按新 epoch 计算的有效 login ticket 或 Session。
//!
//! 用例分两类：
//!
//! 1. **可控 barrier**：把 TOCTOU 窗口固定住——先认证、再让改密整体提交、最后才签发。
//!    这条路径在旧实现下必然产出有效凭据，因此是回归的判定基准；真并发用例做不到
//!    稳定命中这个窗口。
//! 2. **真并发**：多路登录与改密同时起跑，断言不变量而不是具体胜负——
//!    任何拿到的凭据都必须仍然可兑换，任何被拒的路径都不得留下有效凭据。

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

use std::{sync::Arc, time::Duration};

use chenxing_auth::{
    auth_factors::{domain::FactorMethod, service::AuthFactorServiceError},
    config::Config,
    sessions::{domain::Session, store::SessionStoreError},
    state::AppState,
    users::{
        credentials::hash_password,
        domain::{AuthenticatedUser, LoginInput, ValidatedRegistration},
        repository::{self as user_repository, PasswordChangeOutcome},
        service::UserServiceError,
    },
};
use tokio::sync::Barrier;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery";
const REPLACEMENT_PASSWORD: &str = "replacement horse battery";

struct Harness {
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    user_id: i64,
    identifier: String,
}

/// 并发用例每一路都要独立占用连接，而改密事务会持有该用户的 advisory 锁。
/// 默认的 2 个连接会让等待锁的事务与等待连接的任务互相排队，把要测的窗口
/// 变成一条串行队列。
async fn isolated_database(database_url: &str) -> chenxing_auth::sqlx::PgPool {
    db_isolation::isolated_pool_with_max_connections(
        "login_authentication_epoch_race",
        database_url,
        16,
    )
    .await
}

async fn setup() -> Harness {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = isolated_database(&database_url).await;
    let key_directory = key_directory::isolated_key_directory("epoch-race");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");

    let suffix = Uuid::new_v4().simple().to_string();
    let identifier = format!("epoch-race-{suffix}");
    let user = user_repository::insert_user(
        &database,
        ValidatedRegistration {
            username: identifier.clone(),
            email: format!("{identifier}@example.com"),
            password: PASSWORD.to_owned(),
            display_name: None,
        },
        hash_password(PASSWORD.to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert race user");

    Harness {
        state,
        database,
        key_directory,
        user_id: user.id,
        identifier,
    }
}

async fn cleanup(harness: &Harness) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(harness.user_id)
        .execute(&harness.database)
        .await
        .expect("cleanup race user");
    let _ = std::fs::remove_dir_all(&harness.key_directory);
}

fn login_input(identifier: &str, password: &str) -> LoginInput {
    LoginInput {
        identifier: identifier.to_owned(),
        password: password.to_owned(),
        totp_code: None,
    }
}

async fn current_epoch(pool: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session epoch")
}

async fn change_password(harness: &Harness, from: &str, to: &str) {
    harness
        .state
        .users
        .change_password(harness.user_id, from, to, Some("127.0.0.1"))
        .await
        .expect("change password");
}

/// 认证结果携带的 epoch 必须是读取凭据那一刻的值，而不是签发时刻重新读到的值。
#[tokio::test]
async fn authentication_result_carries_the_epoch_read_with_the_password_hash() {
    let harness = setup().await;

    let authenticated = harness
        .state
        .users
        .authenticate(login_input(&harness.identifier, PASSWORD), Some("127.0.0.1"))
        .await
        .expect("authenticate with initial password");
    assert_eq!(authenticated.id, harness.user_id);
    assert_eq!(
        authenticated.session_epoch,
        current_epoch(&harness.database, harness.user_id).await,
        "a fresh authentication must observe the current credential version"
    );

    change_password(&harness, PASSWORD, REPLACEMENT_PASSWORD).await;
    let after_change = harness
        .state
        .users
        .authenticate(
            login_input(&harness.identifier, REPLACEMENT_PASSWORD),
            Some("127.0.0.1"),
        )
        .await
        .expect("authenticate with replacement password");
    assert_eq!(
        after_change.session_epoch,
        authenticated.session_epoch + 1,
        "changing the password must advance the epoch carried by later authentications"
    );

    cleanup(&harness).await;
}

/// 可控 barrier：认证 → 改密整体提交 → 才签发 ticket。
///
/// 这正是漏洞窗口。断言两件事：签发被拒绝，且拒绝不产生任何可用 ticket。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_ticket_is_refused_when_the_password_changed_after_authentication() {
    let harness = setup().await;

    // 第一段：完成口令校验，此时 epoch 仍是 0。
    let authenticated = harness
        .state
        .users
        .authenticate(login_input(&harness.identifier, PASSWORD), Some("127.0.0.1"))
        .await
        .expect("authenticate before password change");

    // 第二段：改密事务完整提交，epoch 前进，全部会话被撤销。
    change_password(&harness, PASSWORD, REPLACEMENT_PASSWORD).await;
    assert_eq!(current_epoch(&harness.database, harness.user_id).await, 1);

    // 第三段：用上面那个已经过期的认证结果签发 ticket。
    let error = harness
        .state
        .factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], "holder-hash")
        .await
        .expect_err("stale authentication must not mint a login ticket");
    assert!(
        matches!(error, AuthFactorServiceError::AuthenticationEpochChanged),
        "expected an epoch drift rejection, got {error}"
    );

    cleanup(&harness).await;
}

/// 同一窗口下的直接 Session 签发同样必须被拒，且事务不留下任何会话行。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_session_is_refused_when_the_password_changed_after_authentication() {
    let harness = setup().await;

    let authenticated = harness
        .state
        .users
        .authenticate(login_input(&harness.identifier, PASSWORD), Some("127.0.0.1"))
        .await
        .expect("authenticate before password change");
    change_password(&harness, PASSWORD, REPLACEMENT_PASSWORD).await;

    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout(harness.user_id.to_string(), ttl, ttl)
        .expect("candidate session");
    let error = harness
        .state
        .sessions
        .save_authenticated(&mut session, ttl, authenticated.session_epoch)
        .await
        .expect_err("stale authentication must not mint a session");
    assert!(
        matches!(error, SessionStoreError::AuthenticationEpochChanged),
        "expected an epoch drift rejection, got {error}"
    );

    // 失败的校验不得产生有效凭据：连行都不该插入，撤销事件也不该出现。
    let sessions_for_user: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(harness.user_id)
            .fetch_one(&harness.database)
            .await
            .expect("session row count");
    assert_eq!(
        sessions_for_user, 0,
        "a rejected session write must roll back completely"
    );
    assert!(
        harness
            .state
            .sessions
            .find(&session.token)
            .await
            .expect("lookup rejected session")
            .is_none(),
        "the rejected session token must not resolve"
    );

    cleanup(&harness).await;
}

/// 兑换阶段的兜底：ticket 已经签发，改密随后提交。
///
/// ticket 的读取路径按 epoch 判定，因此这张 ticket 直接消失；即使调用方绕过读取
/// 直接拿它的认证身份去写 Session，写入事务也会再拒一次。两层都验。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issued_login_ticket_stops_working_once_the_password_changes() {
    let harness = setup().await;

    let authenticated = harness
        .state
        .users
        .authenticate(login_input(&harness.identifier, PASSWORD), Some("127.0.0.1"))
        .await
        .expect("authenticate before password change");
    let holder_hash = format!("holder-{}", Uuid::new_v4().simple());
    let (ticket_id, ticket) = harness
        .state
        .factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], &holder_hash)
        .await
        .expect("login ticket for the current epoch");
    assert_eq!(ticket.session_epoch, authenticated.session_epoch);
    assert_eq!(
        harness
            .state
            .factors
            .user_id_for_ticket(&ticket_id, &holder_hash)
            .await
            .expect("resolve fresh ticket"),
        Some(harness.user_id)
    );

    change_password(&harness, PASSWORD, REPLACEMENT_PASSWORD).await;

    assert_eq!(
        harness
            .state
            .factors
            .user_id_for_ticket(&ticket_id, &holder_hash)
            .await
            .expect("resolve stale ticket"),
        None,
        "an epoch-stale ticket must not resolve to a user"
    );
    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout(harness.user_id.to_string(), ttl, ttl)
        .expect("candidate session");
    assert!(
        matches!(
            harness
                .state
                .sessions
                .save_authenticated(&mut session, ttl, ticket.session_epoch)
                .await,
            Err(SessionStoreError::AuthenticationEpochChanged)
        ),
        "the ticket's authenticated epoch must not mint a session after a password change"
    );

    cleanup(&harness).await;
}

/// 真并发：多路旧口令登录与一次改密同时起跑。
///
/// 不断言谁赢——赢家取决于调度。断言的是不变量：每一张成功签发的 ticket 都必须
/// 仍然可兑换（即它的 epoch 与库里当前值一致），被拒的路径只允许是 epoch 漂移。
/// 旧实现在这里会产出"签发成功但 epoch 已经属于新口令"的 ticket。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_logins_never_mint_tickets_for_a_superseded_password() {
    let harness = setup().await;
    let concurrency = 6_usize;
    // barrier 覆盖全部登录任务加改密任务，保证改密不是在所有登录都跑完之后才开始。
    let barrier = Arc::new(Barrier::new(concurrency + 1));

    let mut logins = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let users = harness.state.users.clone();
        let factors = harness.state.factors.clone();
        let identifier = harness.identifier.clone();
        let barrier = barrier.clone();
        logins.push(tokio::spawn(async move {
            let holder_hash = format!("holder-{}", Uuid::new_v4().simple());
            barrier.wait().await;
            let authenticated = users
                .authenticate(login_input(&identifier, PASSWORD), Some("127.0.0.1"))
                .await;
            let Ok(authenticated) = authenticated else {
                return None;
            };
            match factors
                .create_login_ticket(authenticated, vec![FactorMethod::Totp], &holder_hash)
                .await
            {
                Ok((ticket_id, ticket)) => Some((ticket_id, holder_hash, ticket)),
                Err(AuthFactorServiceError::AuthenticationEpochChanged) => None,
                Err(error) => panic!("unexpected login ticket failure: {error}"),
            }
        }));
    }

    let changer = {
        let users = harness.state.users.clone();
        let user_id = harness.user_id;
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            users
                .change_password(user_id, PASSWORD, REPLACEMENT_PASSWORD, Some("127.0.0.1"))
                .await
        })
    };

    let mut issued = Vec::new();
    for login in logins {
        if let Some(ticket) = login.await.expect("join login task") {
            issued.push(ticket);
        }
    }
    let change_result = changer.await.expect("join password change task");

    // 改密本身可能因为并发登录烧掉的限流额度而被拒；两种结果都合法，
    // 后续断言按库里的实际 epoch 判定，不假设改密一定成功。
    let epoch_after = current_epoch(&harness.database, harness.user_id).await;
    match &change_result {
        Ok(()) => assert_eq!(epoch_after, 1, "a committed password change advances epoch"),
        Err(UserServiceError::InvalidCredentials | UserServiceError::RateLimited) => {
            assert_eq!(
                epoch_after, 0,
                "a rejected password change must not advance epoch"
            );
        }
        Err(error) => panic!("unexpected password change failure: {error}"),
    }

    for (ticket_id, holder_hash, ticket) in issued {
        assert_eq!(
            ticket.session_epoch, ticket.authenticated().session_epoch,
            "a ticket must report the epoch it was stamped with"
        );
        let resolves = harness
            .state
            .factors
            .user_id_for_ticket(&ticket_id, &holder_hash)
            .await
            .expect("resolve issued ticket");
        if ticket.session_epoch == epoch_after {
            assert_eq!(
                resolves,
                Some(harness.user_id),
                "a ticket stamped with the live epoch must stay redeemable"
            );
        } else {
            assert_eq!(
                resolves, None,
                "a ticket stamped with a superseded epoch must be inert"
            );
        }
        // 无论哪一侧，绝不允许一张 ticket 的 epoch 超过库里的当前值：
        // 那正是"旧口令的认证结果被套用到新 epoch"的签名。
        assert!(
            ticket.session_epoch <= epoch_after,
            "no ticket may carry an epoch newer than the stored credential version"
        );
    }

    cleanup(&harness).await;
}

/// 并发改密：两路都拿着同一个旧口令，只有一路能成功。
///
/// 没有事务内的 epoch 比对时，两路都会用各自读到的旧哈希校验通过，
/// 后到者用一个**已被作废的口令**写入新口令——校验失败却产生了有效凭据。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_password_changes_allow_exactly_one_winner() {
    let harness = setup().await;
    let first_replacement = hash_password("first replacement password".to_owned())
        .await
        .expect("first replacement hash");
    let second_replacement = hash_password("second replacement password".to_owned())
        .await
        .expect("second replacement hash");
    let barrier = Arc::new(Barrier::new(2));

    let first = {
        let pool = harness.database.clone();
        let user_id = harness.user_id;
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            user_repository::change_password_and_revoke_all(&pool, user_id, &first_replacement, 0)
                .await
                .expect("first change")
        })
    };
    let second = {
        let pool = harness.database.clone();
        let user_id = harness.user_id;
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            user_repository::change_password_and_revoke_all(&pool, user_id, &second_replacement, 0)
                .await
                .expect("second change")
        })
    };

    let outcomes = [
        first.await.expect("join first change"),
        second.await.expect("join second change"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PasswordChangeOutcome::Changed)
            .count(),
        1,
        "exactly one concurrent change may commit, got {outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == PasswordChangeOutcome::EpochChanged)
            .count(),
        1,
        "the loser must be rejected by the epoch comparison, got {outcomes:?}"
    );
    assert_eq!(
        current_epoch(&harness.database, harness.user_id).await,
        1,
        "only the winning change may advance the epoch"
    );

    cleanup(&harness).await;
}

/// 认证 epoch 未漂移时，一切照旧：ticket 与 Session 都必须能签发。
///
/// 没有这条，"全都拒绝"也能让上面的用例通过。
#[tokio::test]
async fn unchanged_epoch_still_issues_tickets_and_sessions() {
    let harness = setup().await;

    let authenticated = harness
        .state
        .users
        .authenticate(login_input(&harness.identifier, PASSWORD), Some("127.0.0.1"))
        .await
        .expect("authenticate");
    let holder_hash = format!("holder-{}", Uuid::new_v4().simple());
    let (ticket_id, ticket) = harness
        .state
        .factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], &holder_hash)
        .await
        .expect("login ticket");
    assert_eq!(ticket.user_id, harness.user_id);
    assert_eq!(
        harness
            .state
            .factors
            .user_id_for_ticket(&ticket_id, &holder_hash)
            .await
            .expect("resolve ticket"),
        Some(harness.user_id)
    );

    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout(harness.user_id.to_string(), ttl, ttl)
        .expect("candidate session");
    harness
        .state
        .sessions
        .save_authenticated(&mut session, ttl, ticket.authenticated().session_epoch)
        .await
        .expect("session for a live epoch");
    assert!(
        harness
            .state
            .sessions
            .find(&session.token)
            .await
            .expect("lookup issued session")
            .is_some(),
        "a session issued under the live epoch must resolve"
    );

    cleanup(&harness).await;
}

/// `AuthenticatedUser` 只由凭据读取产生，不能被调用方凭空拼一个更高的 epoch 绕过校验。
///
/// 这条用例锁的是行为而不是类型：给一个库里不存在的 epoch，签发必须失败。
#[tokio::test]
async fn fabricated_epoch_cannot_mint_credentials() {
    let harness = setup().await;
    let fabricated = AuthenticatedUser::new(harness.user_id, 99);

    assert!(
        matches!(
            harness
                .state
                .factors
                .create_login_ticket(fabricated, vec![FactorMethod::Totp], "holder-hash")
                .await,
            Err(AuthFactorServiceError::AuthenticationEpochChanged)
        ),
        "an epoch that never existed must not mint a ticket"
    );
    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout(harness.user_id.to_string(), ttl, ttl)
        .expect("candidate session");
    assert!(
        matches!(
            harness
                .state
                .sessions
                .save_authenticated(&mut session, ttl, fabricated.session_epoch)
                .await,
            Err(SessionStoreError::AuthenticationEpochChanged)
        ),
        "an epoch that never existed must not mint a session"
    );

    cleanup(&harness).await;
}
