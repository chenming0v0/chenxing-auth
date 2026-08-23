//! Issue #302：邮箱匹配值的数据库级不变量。
//!
//! 这个文件覆盖的是"跨越应用层与数据库的那条缝"，纯单元测试碰不到：
//!
//! 1. **唯一性由数据库强制**。绕过应用层直接 INSERT 一个等价书写，必须被
//!    `users_canonical_email_key` 拒绝。补丁前 `UNIQUE (email)` 只看展示值，
//!    大小写不同就能各自注册一个账号。
//! 2. **登录按匹配值查行**。同一个邮箱的任意等价书写都要解析到同一行。
//! 3. **纯 ASCII 地址的 SQL 小写结果与应用层规范化逐字节相等**。测试夹具会直接
//!    比较两者，避免测试或维护 SQL 写入错误的匹配值。
//! 4. **启动期复核会拦下 SQL 无法自证的行**。PostgreSQL 证明不了匹配值与
//!    `EmailAddress` 一致，所以 `db::migrate` 之后按主键分批扫完全表再重算；
//!    只筛 `xn--` 会漏掉 Unicode 域名、错误的纯 ASCII 匹配值和本地部分差异。
//!    键集分页必须覆盖完整 BIGINT，包括维护 SQL 写入的负 id。
//!    落错的行会让其所有者静默无法登录，因此必须拒绝启动而不是放行。
//!
//! 单独一个二进制而不是塞进 `database_schema`：那个文件断言的是 schema 形状，
//! 这里断言的是数据语义与失败行为，夹具（刻意写坏的行）也不共享。

use crate::db_isolation;

use chenxing_auth::users::{
    domain::{LoginInput, validate_login},
    email::EmailAddress,
    repository as user_repository,
};
use std::env;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("users_canonical_email", &database_url).await
}

fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

/// 直接写库插入一个用户，绕过应用层的全部校验。
///
/// 刻意不走 `insert_user`：要验证的正是"绕过应用层时数据库还拦不拦得住"。
async fn insert_raw(
    pool: &chenxing_auth::sqlx::PgPool,
    username: &str,
    email: &str,
    canonical_email: &str,
) -> Result<i64, chenxing_auth::sqlx::Error> {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status)
         VALUES ($1, $2, $3, 'unusable-hash', 'active')
         RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(canonical_email)
    .fetch_one(pool)
    .await
}

/// 绕过 identity 生成器，写入指定主键。
///
/// 基线没有 `id > 0` 约束。维护 SQL 用 `OVERRIDING SYSTEM VALUE` 就能放进负
/// BIGINT，复核如果从 `0` 起游标，这类行会整行消失。
async fn insert_raw_with_id(
    pool: &chenxing_auth::sqlx::PgPool,
    id: i64,
    username: &str,
    email: &str,
    canonical_email: &str,
) -> Result<i64, chenxing_auth::sqlx::Error> {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (id, username, email, canonical_email, password_hash, status)
         OVERRIDING SYSTEM VALUE
         VALUES ($1, $2, $3, $4, 'unusable-hash', 'active')
         RETURNING id",
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(canonical_email)
    .fetch_one(pool)
    .await
}

fn is_canonical_email_conflict(error: &chenxing_auth::sqlx::Error) -> bool {
    let chenxing_auth::sqlx::Error::Database(database_error) = error else {
        return false;
    };
    database_error.constraint() == Some("users_canonical_email_key")
}

/// 等价书写的第二次写入必须被数据库拒绝，即使调用方绕过了应用层。
///
/// 这是本 Issue 的核心：补丁前唯一性建在未完全规范化的展示值上，
/// `Owner@example.com` 与 `owner@example.com` 可以并存为两个账号。
#[tokio::test]
async fn equivalent_spellings_cannot_both_be_inserted() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let canonical = format!("dup-{suffix}@example.com");

    insert_raw(&pool, &format!("dup-a-{suffix}"), &canonical, &canonical)
        .await
        .expect("first insert");

    // 展示值不同（大写本地部分），匹配值相同。
    let error = insert_raw(
        &pool,
        &format!("dup-b-{suffix}"),
        &canonical.to_ascii_uppercase(),
        &canonical,
    )
    .await
    .expect_err("an equivalent spelling must be rejected by the database");
    assert!(
        is_canonical_email_conflict(&error),
        "expected users_canonical_email_key violation, got: {error:?}"
    );
}

/// Unicode 与 Punycode 两种书写指向同一个账号，第二次写入同样被拒。
///
/// 这条是补丁前漏得最彻底的一类：`to_ascii_lowercase` 完全不碰非 ASCII 字节，
/// 两种形态在展示值上毫无相似之处，`UNIQUE (email)` 形同不存在。
#[tokio::test]
async fn unicode_and_punycode_spellings_collide_in_the_database() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let unicode = email_address(format!("user-{suffix}@éxample.com"));
    let punycode = email_address(format!("USER-{suffix}@XN--XAMPLE-9UA.COM"));
    assert_eq!(
        unicode.canonical(),
        punycode.canonical(),
        "the two spellings must share one matching value"
    );

    insert_raw(
        &pool,
        &format!("idna-a-{suffix}"),
        unicode.display(),
        unicode.canonical(),
    )
    .await
    .expect("first insert");

    let error = insert_raw(
        &pool,
        &format!("idna-b-{suffix}"),
        punycode.display(),
        punycode.canonical(),
    )
    .await
    .expect_err("the punycode spelling must resolve to the existing account");
    assert!(
        is_canonical_email_conflict(&error),
        "expected users_canonical_email_key violation, got: {error:?}"
    );
}

/// 登录按匹配值查行：任意等价书写都命中同一个账号。
#[tokio::test]
async fn login_resolves_every_equivalent_spelling_to_one_account() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let stored = email_address(format!("login-{suffix}@éxample.com"));
    let user_id = insert_raw(
        &pool,
        &format!("login-{suffix}"),
        stored.display(),
        stored.canonical(),
    )
    .await
    .expect("insert login user");

    for spelling in [
        format!("login-{suffix}@éxample.com"),
        format!("LOGIN-{suffix}@ÉXAMPLE.COM"),
        format!("login-{suffix}@xn--xample-9ua.com"),
        format!("  Login-{suffix}@Xn--Xample-9ua.Com  "),
    ] {
        let login = validate_login(LoginInput {
            identifier: spelling.clone(),
            password: "irrelevant-but-non-empty".to_owned(),
            totp_code: None,
        })
        .unwrap_or_else(|error| panic!("{spelling:?} must validate: {error:?}"));

        let credentials = user_repository::find_credentials_by_identifier(&pool, &login.identifier)
            .await
            .expect("credential lookup")
            .unwrap_or_else(|| panic!("{spelling:?} must resolve to the stored account"));
        assert_eq!(credentials.id, user_id, "{spelling:?}");
        // 限流与审计的账号维度键也必须收敛到同一个值。
        assert_eq!(
            login.identifier.limiter_key(),
            stored.canonical(),
            "{spelling:?}"
        );
        assert_eq!(
            credentials.canonical_email,
            stored.canonical(),
            "{spelling:?}"
        );
    }
}

/// 用户名登录仍然只比 `username` 列，不受邮箱列影响。
///
/// 分流后两列各查各的；这条守住"改邮箱匹配没有顺带改坏用户名登录"。
#[tokio::test]
async fn username_login_still_matches_only_the_username_column() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("uname-{suffix}");
    let email = email_address(format!("other-{suffix}@example.com"));
    let user_id = insert_raw(&pool, &username, email.display(), email.canonical())
        .await
        .expect("insert username user");

    let login = validate_login(LoginInput {
        identifier: format!("  {}  ", username.to_ascii_uppercase()),
        password: "irrelevant-but-non-empty".to_owned(),
        totp_code: None,
    })
    .expect("username identifier must validate");
    let credentials = user_repository::find_credentials_by_identifier(&pool, &login.identifier)
        .await
        .expect("credential lookup")
        .expect("username must resolve");
    assert_eq!(credentials.id, user_id);
}

/// 纯 ASCII 地址的 `lower(email)` 必须与应用层规范化逐字节相等。
///
/// 应用层是权威实现；这个用例覆盖测试和维护 SQL 会使用的保守 ASCII 范围。
#[tokio::test]
async fn ascii_lowercase_agrees_with_the_application_canonicalizer() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    // 全部是纯 ASCII 且结构合法的形态。
    let raw_emails = [
        format!("plain-{suffix}@example.com"),
        format!("MiXeD-{suffix}@Example.COM"),
        format!("Upper-{suffix}@EXAMPLE.COM"),
        format!("dotted.local-{suffix}@sub.example.com"),
        format!("alias-{suffix}+tag@example.com"),
        format!("under-{suffix}@a_b.example"),
        format!("hyphen-{suffix}@ex-ample.example"),
        format!("puny-{suffix}@xn--xample-9ua.com"),
        format!("deep-{suffix}@a.b.c.example.com"),
    ];

    for (index, raw) in raw_emails.iter().enumerate() {
        // 用 lower(email) 模拟测试夹具或维护 SQL 的保守写法。
        chenxing_auth::sqlx::query(
            "INSERT INTO users (username, email, canonical_email, password_hash, status)
             VALUES ($1, $2, lower($2), 'unusable-hash', 'active')",
        )
        .bind(format!("backfill-{index}-{suffix}"))
        .bind(raw)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("insert {raw:?}: {error}"));
    }

    let rows: Vec<(String, String)> = chenxing_auth::sqlx::query_as(
        "SELECT email, canonical_email FROM users WHERE username LIKE $1 ORDER BY id",
    )
    .bind(format!("backfill-%-{suffix}"))
    .fetch_all(&pool)
    .await
    .expect("read back the backfilled rows");
    assert_eq!(rows.len(), raw_emails.len());

    for (email, canonical_email) in rows {
        let expected = email_address(&email);
        assert_eq!(
            canonical_email,
            expected.canonical(),
            "SQL backfill disagrees with the application canonicalizer for {email:?}"
        );
    }
}

/// 插入一行错误匹配值，断言 migrate 拒绝启动且不回显地址，删掉后再放行。
async fn assert_startup_rejects_then_recovers(
    pool: &chenxing_auth::sqlx::PgPool,
    username: &str,
    email: &str,
    stored_canonical: &str,
) {
    insert_raw(pool, username, email, stored_canonical)
        .await
        .expect("the raw insert itself is not constrained");

    let error = chenxing_auth::db::migrate(pool)
        .await
        .expect_err("startup must refuse to proceed with a mismatched matching value");
    let rendered = error.to_string();
    assert!(
        rendered.contains("canonical_email mismatch"),
        "unexpected error: {rendered}"
    );
    // 消息里不得出现邮箱本身：它会进启动日志，属于个人数据。
    assert!(
        !rendered.contains(email),
        "the startup error must not echo the address: {rendered}"
    );
    assert!(
        !rendered.contains(stored_canonical),
        "the startup error must not echo the stored matching value: {rendered}"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await
        .expect("remove the broken row");
    chenxing_auth::db::migrate(pool)
        .await
        .expect("startup must proceed once the offending row is fixed");
}

/// 启动期复核必须拦下匹配值落错的 IDNA 行，而不是放行。
///
/// 这类行的所有者会静默无法登录，且错误表现为"密码不对"。SQL 无法验证 Punycode
/// 的有效性，所以这一步只能由 `db::migrate` 之后的 Rust 复核兜住。
#[tokio::test]
async fn startup_verification_rejects_a_wrong_idna_matching_value() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    // `xn--a-ecp` 形态看似是 Punycode，但并不是有效编码：
    // 应用层的 `EmailAddress::parse` 会拒绝它，于是复核必须报错。
    let broken = format!("broken-{suffix}@xn--a-ecp.example");
    assert_startup_rejects_then_recovers(&pool, &format!("broken-{suffix}"), &broken, &broken)
        .await;
}

/// Unicode 域名若按 `lower(email)` 落库，匹配值里不会出现 `xn--`。
///
/// 旧复核只筛 Punycode 标签，这类行会直接放行，登录却对不上。
#[tokio::test]
async fn startup_verification_rejects_unicode_domain_stored_without_punycode() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let display = format!("User-{suffix}@ÉXAMPLE.COM");
    let naive_lower = display.to_lowercase();
    assert!(
        !naive_lower.contains("xn--"),
        "fixture must be invisible to an xn-- filter: {naive_lower}"
    );

    assert_startup_rejects_then_recovers(
        &pool,
        &format!("unicode-{suffix}"),
        &display,
        &naive_lower,
    )
    .await;
}

/// 纯 ASCII 行的错误匹配值同样必须拦住。
///
/// 旧复核假定这类行由应用写入契约保证，绕过应用层的维护 SQL 就能把错误值留下。
#[tokio::test]
async fn startup_verification_rejects_a_wrong_ascii_matching_value() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let display = format!("user-{suffix}@Example.COM");
    assert_startup_rejects_then_recovers(&pool, &format!("ascii-{suffix}"), &display, &display)
        .await;
}

/// 只差本地部分大小写的匹配值也必须拦住。
///
/// 域名已经是 ASCII 小写时，旧 `xn--` 过滤完全看不见这类漂移。
#[tokio::test]
async fn startup_verification_rejects_local_part_case_drift() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let display = format!("John.Doe-{suffix}@example.com");
    assert_startup_rejects_then_recovers(&pool, &format!("local-{suffix}"), &display, &display)
        .await;
}

/// 有效的 ASCII 与国际化域名行不得被全表复核误伤。
///
/// 判定过严会把正常账号挡在启动之外，那是一个比它要防的问题更糟的故障。
#[tokio::test]
async fn startup_verification_accepts_valid_ascii_and_idna_rows() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let ascii = email_address(format!("Valid-{suffix}@Example.COM"));
    let idna = email_address(format!("Valid-{suffix}@ÉXAMPLE.COM"));
    assert!(
        idna.canonical().contains("xn--"),
        "fixture must exercise the IDNA branch"
    );

    insert_raw(
        &pool,
        &format!("valid-ascii-{suffix}"),
        ascii.display(),
        ascii.canonical(),
    )
    .await
    .expect("insert a valid ASCII row");
    insert_raw(
        &pool,
        &format!("valid-idna-{suffix}"),
        idna.display(),
        idna.canonical(),
    )
    .await
    .expect("insert a valid IDNA row");

    chenxing_auth::db::migrate(&pool)
        .await
        .expect("valid ASCII and IDNA rows must not block startup");
}

/// 夹在合法 IDNA 行中间的错误 ASCII 行也必须被发现。
///
/// 这是 #461 的回归锁：全表扫描之前，旁边有 `xn--` 行也救不了漏掉的纯 ASCII 错误。
#[tokio::test]
async fn startup_verification_finds_ascii_mismatch_among_valid_idna_rows() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let idna = email_address(format!("Keep-{suffix}@ÉXAMPLE.COM"));
    insert_raw(
        &pool,
        &format!("keep-idna-{suffix}"),
        idna.display(),
        idna.canonical(),
    )
    .await
    .expect("insert a valid IDNA neighbor");

    let broken = format!("Drift-{suffix}@example.com");
    assert_startup_rejects_then_recovers(&pool, &format!("drift-ascii-{suffix}"), &broken, &broken)
        .await;
}

/// 负主键行必须进入复核。夹具用 [`i64::MIN`]：它同时打中从 `0` 起游标和
/// `id > i64::MIN` 两种漏扫。
#[tokio::test]
async fn startup_verification_rejects_mismatch_on_negative_user_id() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("neg-id-{suffix}");
    let display = format!("neg-{suffix}@Example.COM");

    let inserted = insert_raw_with_id(&pool, i64::MIN, &username, &display, &display)
        .await
        .expect("maintenance SQL can insert a negative BIGINT id");
    assert_eq!(inserted, i64::MIN);

    let error = chenxing_auth::db::migrate(&pool)
        .await
        .expect_err("a negative-id mismatch must still refuse startup");
    let rendered = error.to_string();
    assert!(
        rendered.contains("canonical_email mismatch"),
        "unexpected error: {rendered}"
    );
    assert!(
        rendered.contains(&i64::MIN.to_string()),
        "the startup error must name the negative id: {rendered}"
    );
    assert!(
        !rendered.contains(&display),
        "the startup error must not echo the address: {rendered}"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(i64::MIN)
        .execute(&pool)
        .await
        .expect("remove the negative-id row");
    chenxing_auth::db::migrate(&pool)
        .await
        .expect("startup must proceed once the offending row is fixed");
}
