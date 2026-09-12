#![allow(dead_code)]

//! 共享集成测试脚手架：统一 49 个测试文件里各自手写的 `async fn setup()`。
//!
//! 历史包袱是每个测试文件都自己拼 Config / AppState / Router，admin token、
//! `max_connections`、Redis keyspace、owner 引导、`isolate_user_ids` 各写各的，
//! 稍有偏差就产生环境态串扰。`HarnessBuilder` 把这条链路收敛成一个显式配置面。
//!
//! ## 模块声明约定
//!
//! `harness.rs` 由每个测试目标的 `mod.rs` 通过 `#[path = "../support/harness.rs"]`
//! 引入，因此模块树里的 `super` 指向该测试目标的 crate 根。调用方必须自行声明
//! 以下兄弟支持模块，`harness.rs` 通过 `super::` 引用它们：
//!
//! ```rust,ignore
//! #[path = "../support/db_isolation.rs"]
//! mod db_isolation;
//! #[path = "../support/oauth_flow.rs"]
//! mod oauth_flow;
//! #[path = "../support/harness.rs"]
//! mod harness;
//! ```
//!
//! `key_directory` 与 `qps_window` 是 `harness.rs` 的私有子模块，由本文件用
//! `#[path]` 自行声明，调用方无需（也不应）额外声明。
//!
//! ## 用法
//!
//! ```rust,ignore
//! let harness = HarnessBuilder::new("my_test_target")
//!     .admin_token("my-admin-token")
//!     .max_connections(10)
//!     .bootstrap_owner()
//!     .build()
//!     .await;
//! ```

use axum::Router;
use chenxing_auth::{api, config::Config, redis_keyspace::RedisKeyspace, state::AppState};

#[path = "key_directory.rs"]
mod key_directory;

#[path = "qps_window.rs"]
mod qps_window;

/// 已构建的测试环境。
///
/// `router`、`state` 与 `database` 指向同一份隔离 schema；`key_directory` 是该
/// 用例独占的签名密钥副本，退出前可用 [`Harness::cleanup`] 清理。
pub struct Harness {
    pub router: Router,
    pub state: AppState,
    pub database: chenxing_auth::sqlx::PgPool,
    pub key_directory: std::path::PathBuf,
    pub admin_token: String,
    pub binary_name: String,
}

/// 构建 [`Harness`] 的链式配置器。
///
/// 默认值对齐 `oauth_flow::test_state_with_max_connections_and_keyspace`：
/// admin token `flow-admin-token`、`max_connections = 2`、默认 Redis keyspace、
/// 不引导 owner、不做额外 user id 隔离、`cookie_secure = false`、无额外配置钩子。
pub struct HarnessBuilder {
    binary_name: String,
    admin_token: String,
    max_connections: u32,
    redis_keyspace: RedisKeyspace,
    bootstrap_owner: bool,
    isolate_ids: bool,
    configure: Option<Box<dyn FnOnce(&mut Config) + Send + 'static>>,
}

impl HarnessBuilder {
    /// 以隔离标签 `binary_name` 创建构建器，同时作为 schema 隔离边界与默认身份后缀。
    pub fn new(binary_name: &str) -> Self {
        Self {
            binary_name: binary_name.to_owned(),
            admin_token: "flow-admin-token".to_owned(),
            max_connections: 2,
            redis_keyspace: RedisKeyspace::default(),
            bootstrap_owner: false,
            isolate_ids: false,
            configure: None,
        }
    }

    /// 覆盖 `admin_token`。
    pub fn admin_token(mut self, token: &str) -> Self {
        self.admin_token = token.to_owned();
        self
    }

    /// 覆盖应用连接池上限。
    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = n;
        self
    }

    /// 覆盖 Redis 键空间前缀，用于需要独立 Redis 边界的用例。
    pub fn redis_keyspace(mut self, keyspace: RedisKeyspace) -> Self {
        self.redis_keyspace = keyspace;
        self
    }

    /// 在 Router 构建后引导首个 Owner。
    ///
    /// 内部调用 `oauth_flow::ensure_owner_bootstrapped`，它自身会顺带收敛
    /// `isolate_user_ids`，因此单独使用本开关即可同时完成两件事。
    pub fn bootstrap_owner(mut self) -> Self {
        self.bootstrap_owner = true;
        self
    }

    /// 在 Router 构建后把用户序列推进到本用例派生的高位区间。
    ///
    /// 与 [`HarnessBuilder::bootstrap_owner`] 一起使用时后者已经做过一次，
    /// 这里是幂等的向前推进。
    pub fn isolate_user_ids(mut self) -> Self {
        self.isolate_ids = true;
        self
    }

    /// 在默认 Config 字段全部落定之后、`AppState::new_with_pool` 之前应用自定义配置。
    ///
    /// 用于覆盖 `oauth_provider_loopback_enabled`、`cltermux`、自定义 issuer 等
    /// 不在默认面上的字段。
    pub fn configure(mut self, f: impl FnOnce(&mut Config) + Send + 'static) -> Self {
        self.configure = Some(Box::new(f));
        self
    }

    /// 产出 [`Harness`]。
    pub async fn build(self) -> Harness {
        let bootstrap_owner = self.bootstrap_owner;
        let isolate_ids = self.isolate_ids;
        let (state, database, key_directory, admin_token, binary_name) = self.build_state().await;
        let router = api::router(state.clone());

        if bootstrap_owner {
            super::oauth_flow::ensure_owner_bootstrapped(
                &router,
                &database,
                &binary_name,
                &binary_name,
            )
            .await;
        }
        if isolate_ids {
            super::db_isolation::isolate_user_ids(&database, &binary_name).await;
        }

        Harness {
            router,
            state,
            database,
            key_directory,
            admin_token,
            binary_name,
        }
    }

    /// 只构建 `AppState`，不构建 Router，也不执行 owner 引导 / user id 隔离。
    ///
    /// 给少数需要在 `api::router` 之前异步改动 `state` 的用例（例如注册 legacy
    /// provider）使用；普通用例应直接调 [`HarnessBuilder::build`]。
    pub async fn build_state(
        self,
    ) -> (
        AppState,
        chenxing_auth::sqlx::PgPool,
        std::path::PathBuf,
        String,
        String,
    ) {
        let Self {
            binary_name,
            admin_token,
            max_connections,
            redis_keyspace,
            configure,
            ..
        } = self;

        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let database = super::db_isolation::isolated_pool_with_max_connections(
            &binary_name,
            &database_url,
            max_connections,
        )
        .await;
        let key_directory = key_directory::isolated_key_directory(&binary_name);
        let mut config = Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            "http://127.0.0.1:3000".to_owned(),
            database_url,
            redis_url,
            3600,
        )
        .expect("test configuration");
        config.admin_token = admin_token.clone();
        config.cookie_secure = false;
        config.key_directory = key_directory.to_string_lossy().into_owned();
        config.redis_keyspace = redis_keyspace;
        if let Some(configure) = configure {
            configure(&mut config);
        }
        let mut state = AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state");
        // QPS 窗口放大到 60s，限流断言不再依赖请求跑得够快（见 `qps_window`）。
        qps_window::override_qps_window(&mut state);
        (state, database, key_directory, admin_token, binary_name)
    }
}

impl Harness {
    /// 删除该用例独占的签名密钥目录。失败被刻意忽略，清理不应掩盖测试结果。
    pub async fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.key_directory);
    }
}

/// 生成一个随机 UUID 后缀，用于用户名、client slug 等一次性标识。
pub fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
