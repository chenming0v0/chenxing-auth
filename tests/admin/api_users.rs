//! Admin API: server-side user listing limits (split from `api.rs`).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use uuid::Uuid;

use super::api::setup;
use crate::http;

#[tokio::test]
async fn list_users_enforces_server_side_limit() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();

    // 直接批量插入，避免 Argon2 哈希让测试变慢；password_hash 不参与本用例校验。
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, role, status)
         SELECT 'bulk-' || $1::text || '-' || series.i,
                'bulk-' || $1::text || '-' || series.i || '@example.com',
                'bulk-' || $1::text || '-' || series.i || '@example.com',
                'unused-hash',
                'user',
                'active'
         FROM generate_series(1, 260) AS series(i)",
    )
    .bind(&suffix)
    .execute(&database)
    .await
    .expect("bulk insert users");

    let list = |query: &'static str| {
        let router = router.clone();
        async move {
            let response = router
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/admin/users{query}"))
                        .header("authorization", "Bearer bootstrap-admin-token")
                        .body(Body::empty())
                        .expect("list users request"),
                )
                .await
                .expect("list users response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = http::json_body(response).await;
            body.as_array().expect("user array").len()
        }
    };

    // 未提供 limit 时使用默认 50，而不是倾倒 260 条。
    assert_eq!(list("").await, 50);
    // 超过上限的 limit 被 clamp 到 200，即使表里有 260 条。
    assert_eq!(list("?limit=300").await, 200);
    assert_eq!(list("?limit=9223372036854775807").await, 200);
    // limit 为 0 或负数时被纠正到 1。
    assert_eq!(list("?limit=0").await, 1);
    assert_eq!(list("?limit=-5").await, 1);
    // offset 正常翻页；260 条数据里跳过 255 条只剩 5 条。
    assert_eq!(list("?limit=10&offset=255").await, 5);
    // 负 offset 按 0 处理，不报错也不越界。
    assert_eq!(list("?limit=3&offset=-10").await, 3);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE 'bulk-' || $1::text || '-%'")
        .bind(&suffix)
        .execute(&database)
        .await
        .expect("cleanup bulk users");
    let _ = std::fs::remove_dir_all(key_directory);
}
