#![allow(dead_code)]

//! 测试用例的 PostgreSQL schema 隔离。
//!
//! ## 问题（issue #136）
//!
//! 测试套件的所有二进制共享同一个开发数据库。`admin_ui_api` / `admin_api` /
//! `bootstrap_invariant` / `authorization_audit` 在 setup() 里执行
//! `TRUNCATE users RESTART IDENTITY CASCADE`，清空整个 `users` 表。由于
//! `users` 为空时公开注册返回 409 `owner_bootstrap_required`，其他 20+ 个依赖
//! owner 存在的二进制在并行时会系统性失败。即使单线程也不能保证顺序，属于
//! 环境态全局状态依赖。
//!
//! ## 解决方案：per-test schema 隔离
//!
//! 每个测试用例在自己的 Postgres schema 里创建并迁移数据库。schema 命名规则：
//!
//! ```text
//! ctest_{binary_name}_{test_identity}     // 非字母数字字符替换为 _
//! ```
//!
//! 命名确定性保证同一测试名的多次运行复用同一 schema。每次 setup 都先删除并重建，
//! 因此同一 schema 不会携带上一次测试的迁移状态或数据。
//!
//! ## 实现细节
//!
//! - `search_path` 通过 pool 的 `after_connect` 钩子设置到每个连接上。
//! - `db::migrate()` 在 `search_path` 下建表，`_sqlx_migrations` 元数据也在该
//!   schema 里，不同二进制的迁移状态互不干扰。
//! - 应用层代码全部使用非限定表名（`SELECT * FROM users`，而非 `public.users`），
//!   因此 `search_path` 切换对应用代码透明。
//! - 除了验证固定 ID 语义的 `admin_api` / `bootstrap_invariant` 外，测试 schema 的
//!   `users` 序列使用测试身份派生的高位起点，避免 Redis 中按 `user_id` 命名的
//!   TOTP replay / session revocation key 在不同 schema 间碰撞。
//! - `isolated_pool` 返回的 PgPool 必须通过 `AppState::new_with_pool(config, pool)`
//!   传给应用，以替换 `AppState::new` 内部自行建立的、指向 `public` 的 pool。
//!   若不使用 `new_with_pool`，隔离无效。
//! - Redis 中以 UUID、client id 或 ticket id 组成的键天然保持唯一；以 `user_id` 组成
//!   的键由上面的用户序列偏移隔离，不需要对共享 Redis 做全库清理。
//!
//! ## 使用方法
//!
//! ```rust,ignore
//! #[path = "support/db_isolation.rs"]
//! mod db_isolation;
//!
//! async fn setup() -> (Router, PgPool, PathBuf) {
//!     let database_url = ...;
//!     let database = db_isolation::isolated_pool("my_binary_name", &database_url).await;
//!     let config = Config::from_values_with_issuer(...).expect("config");
//!     let state = AppState::new_with_pool(config, database.clone()).await.expect("state");
//!     (api::router(state), database, key_directory)
//! }
//! ```

use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::sqlx::{Connection, PgConnection, PgPool};
use sha2::{Digest, Sha256};

/// 为测试用例创建隔离的 PgPool，在自己的 schema 里运行迁移。
///
/// `binary_name` 应与 `Cargo.toml` 里的测试二进制名一致。schema 名规则为
/// `ctest_{binary_name}_{test_identity}`，非字母数字字符替换为 `_`，最长 63 字节。
///
/// 每次运行都 DROP CASCADE 已存在的 schema，保证迁移状态干净（避免编辑迁移文件时
/// 的 checksum VersionMismatch）。性能影响可忽略（~100ms per test，nextest 并发摊销）。
///
/// Pool 上限 2 个连接：测试内是串行的，2 个足够，同时避免 32 并发时超过
/// `max_connections = 100` 的服务器限制（32 × 2 = 64）。
pub async fn isolated_pool(binary_name: &str, database_url: &str) -> PgPool {
    isolated_pool_with_max_connections(binary_name, database_url, 2).await
}

/// 为测试用例创建隔离的 PgPool，并使用指定的最大连接数。
pub async fn isolated_pool_with_max_connections(
    binary_name: &str,
    database_url: &str,
    max_connections: u32,
) -> PgPool {
    let test_identity = current_test_identity();
    let schema = schema_name(binary_name, &test_identity);
    // 建 schema 和跑迁移是 owner 的活（CREATE TABLE / GRANT / ALTER FUNCTION），
    // 运行时角色拿不到 CREATE ON DATABASE。角色分离部署下 DATABASE_URL 指向受限的
    // 运行时角色，因此优先用 MIGRATION_DATABASE_URL；单角色环境两者相同，行为不变。
    let owner_url = owner_database_url(database_url);

    // DROP + CREATE：每次运行都从干净状态开始，消除迁移 checksum 问题
    let mut bootstrap = PgConnection::connect(&owner_url)
        .await
        .expect("db_isolation: bootstrap connection");
    chenxing_auth::sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
        .execute(&mut bootstrap)
        .await
        .expect("db_isolation: drop schema");
    chenxing_auth::sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut bootstrap)
        .await
        .expect("db_isolation: create schema");
    drop(bootstrap);

    // 迁移和应用都走 owner 连接。表 owner 必须是迁移角色，否则基线的 REVOKE
    // 对运行时角色不成立。
    //
    // 应用 pool 刻意不用运行时角色：`chenxing_runtime` 是集群全局对象，
    // `database_schema.rs` 里验证审计边界的用例会给它写随机口令，若 39 个测试
    // 二进制都用这个口令连接，一次轮换就会连带打死并发的其他测试和开发服务器。
    // 运行时角色的权限姿态由 `database_schema.rs` 的专用用例单独覆盖。
    let pool = schema_scoped_pool(&owner_url, &schema, max_connections).await;
    chenxing_auth::db::migrate(&pool)
        .await
        .expect("db_isolation: migrate");

    // 应用的少数 Redis 键以 user_id 作为组成部分。每个 schema 都从独立的序列区间
    // 开始，避免测试之间共用 Redis 时把不同 schema 的用户误认为同一个用户。
    if !matches!(binary_name, "admin_api" | "bootstrap_invariant") {
        let user_id_start = user_id_sequence_start(binary_name, &test_identity);
        chenxing_auth::sqlx::query(
            "SELECT setval(pg_get_serial_sequence('users', 'id'), $1, false)",
        )
        .bind(user_id_start)
        .execute(&pool)
        .await
        .expect("db_isolation: set user id sequence");
    }

    pool
}

/// 建 pool 并把 `search_path` 固定到指定 schema。
///
/// `search_path` 必须挂在 pool 的 `after_connect` 上：它对每个新建连接生效。
/// 在一次性连接上 SET 是无效的，那个会话随连接一起销毁。
async fn schema_scoped_pool(database_url: &str, schema: &str, max_connections: u32) -> PgPool {
    let schema = schema.to_owned();
    PgPoolOptions::new()
        .max_connections(max_connections)
        .after_connect(move |connection, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .expect("db_isolation: pool connect")
}

/// owner 连接串：优先 `MIGRATION_DATABASE_URL`，缺失时回落到运行时连接串。
///
/// 回落覆盖单角色开发库：那时运行时角色就是 owner，行为和改动前一致。
fn owner_database_url(runtime_url: &str) -> String {
    std::env::var("MIGRATION_DATABASE_URL")
        .ok()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| runtime_url.to_owned())
}

/// 在测试 bootstrap owner 后重新设置用户序列，避免 Redis 中按 user_id 命名的键碰撞。
pub async fn isolate_user_ids(database: &PgPool, binary_name: &str) {
    if matches!(binary_name, "admin_api" | "bootstrap_invariant") {
        return;
    }
    let user_id_start = user_id_sequence_start(binary_name, &current_test_identity());
    chenxing_auth::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), $1, false)")
        .bind(user_id_start)
        .execute(database)
        .await
        .expect("db_isolation: reset user id sequence after owner bootstrap");
}

fn current_test_identity() -> String {
    if let Some(name) = std::env::var("NEXTEST_TEST_NAME")
        .ok()
        .filter(|name| !name.is_empty())
    {
        return name;
    }

    let thread = std::thread::current();
    if let Some(name) = thread.name() {
        return name.to_owned();
    }

    format!("{:?}", thread.id())
}

/// 将测试二进制名和测试身份转换为合法 Postgres schema 名。
///
/// 规则：`ctest_` 前缀 + binary name + test identity，所有非 ASCII 字母数字字符
/// 替换为 `_`，长度截断到 63 字节。输出始终为 ASCII，因此字符数也是字节数。
pub(crate) fn schema_name(binary_name: &str, test_identity: &str) -> String {
    let readable: String = format!("ctest_{binary_name}_{test_identity}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let digest = Sha256::digest(format!("{binary_name}\0{test_identity}").as_bytes());
    let hash: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let prefix_length = 63 - hash.len() - 1;
    format!(
        "{}_{}",
        readable.chars().take(prefix_length).collect::<String>(),
        hash
    )
}

fn user_id_sequence_start(binary_name: &str, test_identity: &str) -> i64 {
    let digest = Sha256::digest(format!("{binary_name}\0{test_identity}").as_bytes());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    1_000_000 + (u64::from_be_bytes(bytes) % 1_000_000_000_000) as i64
}
