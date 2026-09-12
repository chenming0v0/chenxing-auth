use super::{
    DB_MODULE, DB_POOL_MODULE, ENV_EXAMPLE, HEALTH_MODULE, OAUTH_ERROR_MODULE,
    OAUTH_RESPONSE_MODULE, OAUTH_TOKEN_SUPPORT_MODULE,
};

#[test]
fn signing_failures_map_to_oauth_unavailable_and_gate_readiness() {
    for (module, marker) in [
        (OAUTH_RESPONSE_MODULE, "state.keys.signing_ready()"),
        (
            OAUTH_RESPONSE_MODULE,
            "error::oauth_temporarily_unavailable()",
        ),
        (OAUTH_TOKEN_SUPPORT_MODULE, "state.keys.signing_ready()"),
        (
            OAUTH_TOKEN_SUPPORT_MODULE,
            "OAuthError::temporarily_unavailable()",
        ),
        (OAUTH_ERROR_MODULE, "\"temporarily_unavailable\""),
        (
            HEALTH_MODULE,
            "let signing_ready = state.keys.signing_ready();",
        ),
        (HEALTH_MODULE, "signing_ready,"),
        (HEALTH_MODULE, "workers.ready"),
    ] {
        assert!(
            module.contains(marker),
            "signing/readiness marker missing: {marker}"
        );
    }
}

#[test]
fn application_startup_does_not_mutate_schema_outside_migrations() {
    let main = include_str!("../../../src/main.rs");
    assert!(main.contains("\"migrate\""));
    assert!(!main.contains("db::migrate(&state.database)"));
    assert!(!main.contains("CREATE TABLE"));
    assert!(!main.contains("ALTER TABLE"));
}

/// Issue #267：请求路径必须带服务端语句上限，维护路径必须不带。
///
/// 断言写在源码文本上，因为这个不变量的代价在生产才显现：只有真实 PostgreSQL 能
/// 观察到 `statement_timeout` 生效，而这里要守住的是"谁走哪个池"这个结构决定，
/// 不需要数据库就能验证，也不会被集成测试环境缺失掩盖。
#[test]
fn request_path_pool_enforces_statement_timeout_and_maintenance_pool_does_not() {
    assert!(
        DB_POOL_MODULE.contains("DB_STATEMENT_TIMEOUT_MS"),
        "statement timeout must be configurable"
    );
    assert!(
        DB_MODULE.contains("set_config('statement_timeout', $1, false)"),
        "statement timeout must be applied per connection as a bound parameter"
    );
    assert!(
        DB_MODULE.contains("PoolRole::Maintenance => None"),
        "the maintenance pool must not carry a statement timeout"
    );

    // 迁移与归档命令必须显式走维护池，否则长任务会被请求路径的上限截断。
    let main = include_str!("../../../src/main.rs");
    assert!(!main.contains("db::connect_with_url("));
    assert_eq!(
        main.matches("db::connect_maintenance(").count(),
        3,
        "migration owner/runtime verification and `audit-archive` must use the maintenance pool"
    );

    assert!(
        ENV_EXAMPLE.contains("DB_STATEMENT_TIMEOUT_MS"),
        "the tunable must be documented in .env.example"
    );
}
