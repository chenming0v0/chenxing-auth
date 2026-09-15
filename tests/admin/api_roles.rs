//! Admin API: session/login flows (split from `api.rs`).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use uuid::Uuid;

use super::api::{browser_session, setup};
use crate::http;

#[tokio::test]
async fn owner_role_mutation_is_owner_only_and_updates_existing_sessions() {
    let (router, database, key_directory) = setup().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}");
    let owner_email = format!("{owner}@example.com");
    let password = "1234567890";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": owner, "email": owner_email, "password": password}).to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_user = |username: String, email: String| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "email": email, "password": password, "role": "admin"}).to_string(),
                ))
                .expect("create privileged user request"),
        )
    };
    let response = create_user(
        format!("managed-{suffix}"),
        format!("managed-{suffix}@example.com"),
    )
    .await
    .expect("create privileged user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let managed_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("managed user id");

    let (managed_cookie, managed_csrf) = browser_session(&database, &redis_url, managed_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &managed_cookie)
                .body(Body::empty())
                .expect("managed session request"),
        )
        .await
        .expect("managed session response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{managed_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "user"}).to_string()))
                .expect("role mutation request"),
        )
        .await
        .expect("role mutation response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &managed_cookie)
                .body(Body::empty())
                .expect("demoted session request"),
        )
        .await
        .expect("demoted session response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (owner_cookie, owner_csrf) = browser_session(&database, &redis_url, 1).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/1/role")
                .header("cookie", &owner_cookie)
                .header("x-csrf-token", owner_csrf)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("self role mutation request"),
        )
        .await
        .expect("self role mutation response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = create_user(
        format!("second-owner-{suffix}"),
        format!("second-owner-{suffix}@example.com"),
    )
    .await
    .expect("create second owner response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let second_admin_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("second admin id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{second_admin_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "owner"}).to_string()))
                .expect("promote second owner request"),
        )
        .await
        .expect("promote second owner response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 使用仍为 Admin 的独立会话验证 #424；managed_cookie 已因上面的角色降权被撤销，
    // 不能再拿它区分认证失败和权限失败。
    let response = create_user(
        format!("peer-admin-{suffix}"),
        format!("peer-admin-{suffix}@example.com"),
    )
    .await
    .expect("create peer admin response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let peer_admin_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("peer admin id");
    let (peer_cookie, peer_csrf) = browser_session(&database, &redis_url, peer_admin_id).await;

    // 禁用 Owner 属于角色管理：只有 ManageUsers 的 Admin 不得绕过 ManageRoles。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{second_admin_id}/disabled"))
                .header("cookie", &peer_cookie)
                .header("x-csrf-token", &peer_csrf)
                .body(Body::empty())
                .expect("disable owner request"),
        )
        .await
        .expect("disable owner response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(http::json_body(response).await["code"], "admin_forbidden");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/1/role")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("demote first owner request"),
        )
        .await
        .expect("demote first owner response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{second_admin_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("demote last owner request"),
        )
        .await
        .expect("demote last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let _ = managed_csrf;
    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

/// `POST /api/v1/admin/users`（Issue #133）。
///
/// 覆盖三件事：成功路径返回落库后的 PublicUser 且不含任何凭据材料、
/// 输入错误落到 400/409 而不是 500、提升角色时权限被抬到 ManageRoles。
#[tokio::test]
async fn admin_user_creation_covers_success_validation_and_role_escalation() {
    let (router, database, key_directory) = setup().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let suffix = Uuid::new_v4().simple().to_string();
    let password = "1234567890";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let create = |body: serde_json::Value| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("create user request"),
        )
    };

    // 默认角色与状态：不传 role/status 时必须落成最低权限的活跃账号。
    let response = create(serde_json::json!({
        "username": format!("managed-{suffix}"),
        "email": format!("managed-{suffix}@example.com"),
        "password": password
    }))
    .await
    .expect("create default user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = http::json_body(response).await;
    assert_eq!(created["role"], "user");
    assert_eq!(created["status"], "active");
    assert_eq!(created["username"], format!("managed-{suffix}"));
    // display_name 缺省保持 NULL，不回填 username。
    assert!(created["display_name"].is_null());
    assert!(created["id"].as_i64().is_some());
    // 响应不得包含任何凭据材料。
    assert!(created.get("password").is_none());
    assert!(created.get("password_hash").is_none());

    // 显式 disabled 状态必须落库，而不是被忽略成 active。
    let response = create(serde_json::json!({
        "username": format!("suspended-{suffix}"),
        "email": format!("suspended-{suffix}@example.com"),
        "password": password,
        "display_name": "  ",
        "status": "disabled"
    }))
    .await
    .expect("create disabled user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = http::json_body(response).await;
    assert_eq!(created["status"], "disabled");
    // 空白 display_name 被 trim 成 NULL。
    assert!(created["display_name"].is_null());

    // 输入错误必须是 400，重复用户名/邮箱必须是 409。
    for (body, status, code) in [
        (
            serde_json::json!({
                "username": format!("badmail-{suffix}"),
                "email": "invalid",
                "password": password
            }),
            StatusCode::BAD_REQUEST,
            "invalid_email",
        ),
        (
            serde_json::json!({
                "username": format!("shortpass-{suffix}"),
                "email": format!("shortpass-{suffix}@example.com"),
                "password": "short"
            }),
            StatusCode::BAD_REQUEST,
            "password_too_short",
        ),
        (
            serde_json::json!({
                "username": "ab",
                "email": format!("baduser-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::BAD_REQUEST,
            "invalid_username",
        ),
        (
            serde_json::json!({
                "username": format!("managed-{suffix}"),
                "email": format!("duplicate-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::CONFLICT,
            "username_already_registered",
        ),
        (
            serde_json::json!({
                "username": format!("duplicate-{suffix}"),
                "email": format!("managed-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::CONFLICT,
            "email_already_registered",
        ),
    ] {
        let response = create(body).await.expect("create user error response");
        assert_eq!(response.status(), status, "{code}");
        assert_eq!(http::json_body(response).await["code"], code);
    }

    // admin 角色只有 ManageUsers，创建 owner 需要 ManageRoles → 403。
    let response = create(serde_json::json!({
        "username": format!("promoted-{suffix}"),
        "email": format!("promoted-{suffix}@example.com"),
        "password": password,
        "role": "admin"
    }))
    .await
    .expect("create admin response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("admin id");
    let (admin_cookie, admin_csrf) = browser_session(&database, &redis_url, admin_id).await;

    let escalate = |role: &'static str| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("escalated-{role}-{suffix}"),
                        "email": format!("escalated-{role}-{suffix}@example.com"),
                        "password": password,
                        "role": role
                    })
                    .to_string(),
                ))
                .expect("escalation request"),
        )
    };
    for role in ["admin", "owner"] {
        let response = escalate(role).await.expect("escalation response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{role}");
        assert_eq!(http::json_body(response).await["code"], "admin_forbidden");
    }

    // 同一个 admin 会话创建普通用户是允许的：ManageUsers 就够了。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("by-admin-{suffix}"),
                        "email": format!("by-admin-{suffix}@example.com"),
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin session create request"),
        )
        .await
        .expect("admin session create response");
    assert_eq!(response.status(), StatusCode::CREATED);

    // 缺少 X-CSRF-Token 的 Cookie 会话写操作必须被 CSRF 校验拦下。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("no-csrf-{suffix}"),
                        "email": format!("no-csrf-{suffix}@example.com"),
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("missing CSRF request"),
        )
        .await
        .expect("missing CSRF response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(http::json_body(response).await["code"], "csrf_invalid");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE '%' || $1::text")
        .bind(&suffix)
        .execute(&database)
        .await
        .expect("cleanup created users");
    let _ = std::fs::remove_dir_all(key_directory);
}
