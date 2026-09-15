//! Bootstrap owner audit invariants (split from `bootstrap_invariant.rs`).

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

use super::bootstrap_invariant::{setup, unique_test_ip};
use crate::http;

/// 引导相关的全部审计事件（成功与被拒共用同一个 action）。
async fn bootstrap_events(
    database: &chenxing_auth::sqlx::PgPool,
) -> Vec<chenxing_auth::audit::AuditEvent> {
    let (events, _total) = chenxing_auth::audit::AuditService::new(database.clone())
        .query(Some("owner_bootstrap"), None, 100, 0)
        .await
        .expect("audit query");
    events
}

/// Issue #304：引导成功的审计记录必须与 Owner 行同一次提交落库。
///
/// 修复前这条审计由 handler 在提交之后 best-effort 写入，审计数据库抖动就能让
/// 「系统里最高权限账号的诞生」永久无记录。现在成功路径必然带来一条
/// `owner_bootstrap` 审计行，且元数据里没有用户名、邮箱或口令。
#[tokio::test]
async fn owner_bootstrap_success_is_audited_in_the_same_commit() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("owner-{suffix}");
    let email = format!("owner-{suffix}@example.com");
    // 源地址与用户名取自不同的随机源：否则两者共享同一段十六进制串，
    // 「审计里没有用户名」的断言可能被 `source_ip` 里的相同子串意外满足或推翻。
    let source = unique_test_ip();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(source, 41010)))
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("owner id");

    let events = bootstrap_events(&database).await;
    assert_eq!(events.len(), 1, "引导成功必须留下且仅留下一条审计事件");
    let event = &events[0];
    assert_eq!(event.actor_type, "bootstrap");
    assert_eq!(event.actor_id, None, "引导时还没有可归属的用户 actor");
    assert_eq!(event.resource_type, "user");
    assert_eq!(event.resource_id, Some(owner_id.to_string()));
    assert_eq!(event.metadata["result"], "success");
    assert_eq!(event.metadata["role"], "owner");
    // 来源可追溯：「谁抢到了 Owner」必须留在审计里，且是规范化后的地址。
    assert_eq!(event.metadata["source_ip"], source.to_string());

    // 个人数据与凭据都不进审计。
    let serialized = serde_json::to_string(event).expect("event serializes");
    assert!(!serialized.contains(&username), "审计不得记录用户名");
    assert!(!serialized.contains(&email), "审计不得记录邮箱");
    assert!(!serialized.contains("1234567890"), "审计不得记录口令");

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 重复引导是拒绝路径：它有自己的审计事件，且不得伪造一条成功记录。
#[tokio::test]
async fn repeat_owner_bootstrap_is_audited_as_a_denial_not_a_success() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let bootstrap_request = |port: u16| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), port)))
            .body(Body::from(
                serde_json::json!({
                    "username": format!("owner-{suffix}"),
                    "email": format!("owner-{suffix}@example.com"),
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    let response = router
        .clone()
        .oneshot(bootstrap_request(41011))
        .await
        .expect("first bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .oneshot(bootstrap_request(41012))
        .await
        .expect("repeat bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        http::json_body(response).await["code"],
        "bootstrap_already_completed"
    );

    let events = bootstrap_events(&database).await;
    assert_eq!(events.len(), 2, "成功与被拒各留一条审计事件");
    let successes = events
        .iter()
        .filter(|event| event.metadata["result"] == "success")
        .count();
    assert_eq!(successes, 1, "引导成功在一个部署里只能出现一次");
    let denial = events
        .iter()
        .find(|event| event.metadata["result"] == "failure")
        .expect("denial event");
    assert_eq!(denial.metadata["reason"], "already_completed");
    // 拒绝事件不指向任何被创建的资源。
    assert_eq!(denial.resource_id, None);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #304：审计写不进去时，引导必须整体回滚。
///
/// 这是整个改动要消除的那个特殊情况：旧实现会留下「Owner 已创建、审计丢失」的
/// 状态，而且响应仍是 201。现在审计 INSERT 在引导事务内，失败即回滚 ——
/// 没有 Owner、没有审计行、响应是可重试的 503，随后重试可以正常完成引导。
///
/// 制造审计故障的手法是把隔离 schema 里的 `audit_events` 改名：`search_path` 指向
/// 本测试独占的 schema，因此不影响其他测试，也不触碰 `public`。改名而不是 DROP，
/// 因为触发器、索引和序列会随表一起改名，改回来即精确恢复；而 DROP 之后
/// `db::migrate` 不会重建它（迁移版本已记录为已应用）。
#[tokio::test]
async fn owner_bootstrap_rolls_back_when_its_audit_record_cannot_be_written() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query("ALTER TABLE audit_events RENAME TO audit_events_unavailable")
        .execute(&database)
        .await
        .expect("hide the audit table inside the isolated schema");

    let bootstrap_request = |port: u16| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), port)))
            .body(Body::from(
                serde_json::json!({
                    "username": format!("owner-{suffix}"),
                    "email": format!("owner-{suffix}@example.com"),
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    let response = router
        .clone()
        .oneshot(bootstrap_request(41013))
        .await
        .expect("bootstrap response with a broken audit table");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "审计不可用时引导必须报可重试的失败，而不是声称创建成功"
    );
    assert_eq!(http::json_body(response).await["code"], "audit_unavailable");

    // 关键断言：没有 Owner 被创建，也没有任何用户行残留。
    let user_count: i64 = chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&database)
        .await
        .expect("user count");
    assert_eq!(
        user_count, 0,
        "审计失败必须连带回滚用户创建，否则会留下无审计的 Owner"
    );

    // 恢复审计能力后重试必须成功：上一次失败没有烧掉引导机会。
    chenxing_auth::sqlx::query("ALTER TABLE audit_events_unavailable RENAME TO audit_events")
        .execute(&database)
        .await
        .expect("restore the audit table");
    let response = router
        .oneshot(bootstrap_request(41014))
        .await
        .expect("retry bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let events = bootstrap_events(&database).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.metadata["result"] == "success")
            .count(),
        1,
        "重试成功后必须恰好有一条成功审计"
    );

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}
