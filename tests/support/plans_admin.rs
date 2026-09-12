#![allow(dead_code)]

//! 套餐管理端 HTTP 辅助：创建 / 更新 / 归档 / 恢复 / 分配 / 列举。

use super::*;

pub async fn submit_plan(
    router: &Router,
    suffix: &str,
    limits: serde_json::Map<String, Value>,
) -> (StatusCode, Value) {
    let mut body = serde_json::Map::new();
    body.insert("code".to_owned(), Value::String(format!("plan-{suffix}")));
    body.insert("name".to_owned(), Value::String(format!("Plan {suffix}")));
    body.insert("description".to_owned(), Value::Null);
    body.insert("is_default".to_owned(), Value::Bool(false));
    body.extend(limits);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(Value::Object(body).to_string()))
                .expect("create plan request"),
        )
        .await
        .expect("create plan response");
    (response.status(), json(response).await)
}

pub async fn create_plan(
    router: &Router,
    suffix: &str,
    limits: serde_json::Map<String, Value>,
) -> Value {
    let (status, body) = submit_plan(router, suffix, limits).await;
    assert_eq!(status, StatusCode::CREATED, "create plan: {body}");
    body
}

/// 常用限额组合，省掉每个测试重复构造 `serde_json::Map`。
pub fn plan_limits(
    oauth_clients_limit: i64,
    daily_auth_limit: i64,
    monthly_auth_limit: Option<i64>,
    max_qps: Option<i64>,
) -> serde_json::Map<String, Value> {
    let mut limits = serde_json::Map::new();
    limits.insert(
        "oauth_clients_limit".to_owned(),
        Value::from(oauth_clients_limit),
    );
    limits.insert("daily_auth_limit".to_owned(), Value::from(daily_auth_limit));
    limits.insert(
        "monthly_auth_limit".to_owned(),
        monthly_auth_limit.map_or(Value::Null, Value::from),
    );
    limits.insert(
        "max_qps".to_owned(),
        max_qps.map_or(Value::Null, Value::from),
    );
    limits
}

pub async fn update_plan(
    router: &Router,
    plan_id: i64,
    code: &str,
    is_default: bool,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/plans/{plan_id}"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "code": code,
                        "name": "Updated plan",
                        "description": null,
                        "oauth_clients_limit": 2,
                        "daily_auth_limit": 2500,
                        "monthly_auth_limit": 50000,
                        "max_qps": null,
                        "is_default": is_default,
                    })
                    .to_string(),
                ))
                .expect("update plan request"),
        )
        .await
        .expect("update plan response");
    let status = response.status();
    (status, json(response).await)
}

pub async fn archive_plan(router: &Router, plan_id: i64) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/plans/{plan_id}/archive"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("archive request"),
        )
        .await
        .expect("archive response")
}

pub async fn restore_plan(router: &Router, plan_id: i64) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/plans/{plan_id}/restore"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("restore request"),
        )
        .await
        .expect("restore response")
}

pub async fn assign_plan(
    router: &Router,
    user_id: i64,
    plan_id: i64,
    expires_at: Option<Value>,
) -> StatusCode {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/plan"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id, "expires_at": expires_at }).to_string(),
                ))
                .expect("assign plan request"),
        )
        .await
        .expect("assign plan response");
    response.status()
}

pub async fn list_plans(router: &Router) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list plans request"),
        )
        .await
        .expect("list plans response");
    assert_eq!(response.status(), StatusCode::OK, "list plans");
    json(response).await
}
