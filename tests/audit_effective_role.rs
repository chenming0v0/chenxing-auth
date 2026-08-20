//! Issue #649：权限校验必须使用连接上的有效 PostgreSQL 主体。
//!
//! 旧实现把 `DATABASE_URL` 用户名传给 `has_table_privilege(role, ...)`。代理、
//! `SET ROLE` 或连接 `options` 可以让 `current_user` 变成 owner，同时 URL 仍写着
//! `chenxing_runtime`。目录检查通过，应用却能改 append-only 审计数据。

use chenxing_auth::sqlx::PgPool;
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use std::env;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn owner_pool() -> PgPool {
    owner_pool_with_max_connections(2).await
}

async fn owner_pool_with_max_connections(max_connections: u32) -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections(
        "audit_effective_role",
        &database_url,
        max_connections,
    )
    .await
}

fn assert_simple_ident(name: &str) -> &str {
    assert!(
        name.chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "refusing to interpolate a non-simple role name: {name}"
    );
    name
}

async fn current_schema(pool: &PgPool) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(pool)
        .await
        .expect("current schema")
}

async fn current_user(pool: &PgPool) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await
        .expect("current_user")
}

async fn configure_runtime(owner: &PgPool) -> url::Url {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let mut runtime_url = url::Url::parse(&database_url).expect("runtime database URL");
    runtime_url
        .set_username(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
        .expect("set runtime username");
    runtime_url
        .set_password(Some(&format!("runtime-{}", uuid::Uuid::new_v4().simple())))
        .expect("set runtime password");
    chenxing_auth::db::configure_runtime_role(
        owner,
        runtime_url.as_str(),
        chenxing_auth::db::RuntimePasswordPolicy::Managed,
    )
    .await
    .expect("configure runtime role");
    runtime_url
}

async fn connect_runtime(owner: &PgPool, runtime_url: &url::Url) -> PgPool {
    let schema = current_schema(owner).await;
    PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(runtime_url.as_str())
        .await
        .expect("runtime role connection")
}

async fn create_switch_role(owner: &PgPool, schema: &str) -> String {
    let schema = assert_simple_ident(schema);
    let role = format!("cx649_{}", uuid::Uuid::new_v4().simple());
    let role = assert_simple_ident(&role).to_owned();
    chenxing_auth::sqlx::query(&format!("CREATE ROLE {role} NOINHERIT NOLOGIN"))
        .execute(owner)
        .await
        .expect("create non-superuser switch role");
    chenxing_auth::sqlx::query(&format!("GRANT USAGE ON SCHEMA {schema} TO {role}"))
        .execute(owner)
        .await
        .expect("grant schema usage to the switch role");
    chenxing_auth::sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON audit_events, audit_events_archive TO {role}"
    ))
    .execute(owner)
    .await
    .expect("grant audit mutation to the switch role");
    chenxing_auth::sqlx::query(&format!(
        "GRANT {role} TO {} WITH INHERIT FALSE, SET TRUE",
        chenxing_auth::db::RUNTIME_DATABASE_ROLE
    ))
    .execute(owner)
    .await
    .expect("allow SET ROLE without inheriting privileges");
    role
}

async fn drop_switch_role(owner: &PgPool, role: &str) {
    let role = assert_simple_ident(role);
    chenxing_auth::sqlx::query(&format!(
        "REVOKE {role} FROM {}",
        chenxing_auth::db::RUNTIME_DATABASE_ROLE
    ))
    .execute(owner)
    .await
    .ok();
    chenxing_auth::sqlx::query(&format!("DROP OWNED BY {role}"))
        .execute(owner)
        .await
        .ok();
    chenxing_auth::sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(owner)
        .await
        .expect("drop switch role");
}

/// 有效主体真的是 chenxing_runtime 且不能改审计表时，校验通过。
#[tokio::test]
async fn verifier_accepts_a_real_runtime_session() {
    let owner = owner_pool().await;
    let runtime_url = configure_runtime(&owner).await;
    let runtime = connect_runtime(&owner, &runtime_url).await;

    let privileges = chenxing_auth::db::verify_audit_append_only_boundary(
        &runtime,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect("a genuine runtime session must satisfy the append-only boundary");
    assert!(privileges.can_insert);
    assert!(privileges.can_select);
    assert!(privileges.can_archive);
    assert!(!privileges.can_mutate);
}

/// URL 写运行时角色、连接却是 owner：这是代理把应用查询跑在 owner 下的失败场景。
#[tokio::test]
async fn verifier_rejects_an_owner_session_that_claims_the_runtime_role_name() {
    let owner = owner_pool().await;
    configure_runtime(&owner).await;

    let error = chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect_err("owner executing under a runtime URL name must fail closed");
    assert!(
        matches!(
            error,
            chenxing_auth::db::AuditBoundaryError::EffectiveRoleMismatch { .. }
        ),
        "verifier must not trust the URL username, got {error}"
    );
}

/// 登录身份是 runtime，但 SET ROLE 让有效主体变成一个能改审计表的角色。
///
/// 不能 SET ROLE 到测试库的 superuser owner（非 superuser 做不到）。这里造一个
/// `NOINHERIT` 的可变角色：`GRANT ... WITH INHERIT FALSE` 保证目录里
/// `chenxing_runtime` 本身仍然不能改表，旧的按名字检查会放行；两参数
/// `has_table_privilege` 看到的是切换后的有效主体。
#[tokio::test]
async fn verifier_rejects_runtime_login_that_set_role_to_a_mutating_principal() {
    let owner = owner_pool().await;
    let runtime_url = configure_runtime(&owner).await;
    let schema = current_schema(&owner).await;
    let switch_role = create_switch_role(&owner, &schema).await;
    let set_role_target = switch_role.clone();
    let runtime = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _meta| {
            let schema = schema.clone();
            let set_role_target = set_role_target.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(&mut *connection)
                    .await?;
                chenxing_auth::sqlx::query("SELECT set_config('role', $1, false)")
                    .bind(set_role_target)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(runtime_url.as_str())
        .await
        .expect("runtime login with SET ROLE to a mutating principal");

    let named_can_delete: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT has_table_privilege($1, 'audit_events', 'DELETE')",
    )
    .bind(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
    .fetch_one(&runtime)
    .await
    .expect("named-role catalog check");
    assert!(
        !named_can_delete,
        "the URL username itself must still look restricted, otherwise this is not the #649 bug"
    );
    let effective_can_delete: bool =
        chenxing_auth::sqlx::query_scalar("SELECT has_table_privilege('audit_events', 'DELETE')")
            .fetch_one(&runtime)
            .await
            .expect("effective principal privilege check");
    assert!(
        effective_can_delete,
        "SET ROLE must make a mutating principal the effective user"
    );

    let verify_result = chenxing_auth::db::verify_audit_append_only_boundary(
        &runtime,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await;
    runtime.close().await;
    drop_switch_role(&owner, &switch_role).await;
    let error = verify_result.expect_err("SET ROLE to a mutating principal must fail closed");
    assert!(
        matches!(
            error,
            chenxing_auth::db::AuditBoundaryError::EffectiveRoleMismatch { .. }
        ),
        "verifier must observe current_user after SET ROLE, got {error}"
    );
}

/// 池里一条连接 SET ROLE 成看起来合法的 runtime，另一条仍是 owner。
///
/// 身份和权限必须在同一次 checkout 上读取：如果先读 current_user 再拿另一条
/// 连接问 named-role 权限，交错会让校验误通过。两条连接各自都对不上
/// `session_user` 或 `current_user`，Require 必须拒绝。
#[tokio::test]
async fn verifier_rejects_set_role_interleaving_across_pooled_sessions() {
    let owner = owner_pool_with_max_connections(2).await;
    configure_runtime(&owner).await;
    let owner_name = current_user(&owner).await;

    {
        let mut switched = owner.acquire().await.expect("acquire pooled connection");
        chenxing_auth::sqlx::query("SELECT set_config('role', $1, false)")
            .bind(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
            .execute(&mut *switched)
            .await
            .expect("SET ROLE runtime on one pooled session");
        let switched_current: String = chenxing_auth::sqlx::query_scalar("SELECT current_user")
            .fetch_one(&mut *switched)
            .await
            .expect("current_user after SET ROLE");
        let switched_session: String = chenxing_auth::sqlx::query_scalar("SELECT session_user")
            .fetch_one(&mut *switched)
            .await
            .expect("session_user after SET ROLE");
        assert_eq!(switched_current, chenxing_auth::db::RUNTIME_DATABASE_ROLE);
        assert_eq!(switched_session, owner_name);
    }

    let error = chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect_err("pooled SET ROLE interleaving must fail closed");
    assert!(
        matches!(
            error,
            chenxing_auth::db::AuditBoundaryError::EffectiveRoleMismatch { .. }
        ),
        "session_user or current_user must disagree with the URL username, got {error}"
    );
}

/// allow-single-role 仍是显式逃生口：有效主体能改表时只降级告警。
#[tokio::test]
async fn allow_single_role_still_accepts_an_owner_principal_with_a_warning() {
    let owner = owner_pool().await;
    let owner_name = current_user(&owner).await;
    let degraded = chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        &owner_name,
        chenxing_auth::db::AuditRoleSeparation::AllowSingleRole,
    )
    .await
    .expect("the explicit switch downgrades the failure to a warning");
    assert!(degraded.can_mutate);
}
