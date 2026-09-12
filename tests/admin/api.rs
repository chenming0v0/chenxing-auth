use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::sessions::{cookies, domain::Session, store::SessionStore};
use tower::ServiceExt;
use uuid::Uuid;

use crate::http;

pub(super) async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let harness = crate::harness::HarnessBuilder::new("admin_api")
        .admin_token("bootstrap-admin-token")
        .build()
        .await;
    (harness.router, harness.database, harness.key_directory)
}

pub(super) async fn browser_session(
    database: &chenxing_auth::sqlx::PgPool,
    redis_url: &str,
    user_id: i64,
) -> (String, String) {
    let redis = redis::Client::open(redis_url).expect("session Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::session_cookie_name(false),
        session.token,
        cookies::csrf_cookie_name(false),
        session.csrf_token
    );
    (cookie, session.csrf_token)
}

#[tokio::test]
async fn bootstrap_admin_can_login_and_use_cookie_session() {
    let (router, database, key_directory) = setup().await;
    let username = format!("admin-{}", Uuid::new_v4().simple());
    let email = format!("{username}@example.com");
    let password = "1234567890";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("bootstrap status request"),
        )
        .await
        .expect("bootstrap status response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(http::json_body(response).await["initialized"], false);

    let contender = format!("contender-{}", Uuid::new_v4().simple());
    let contender_email = format!("{contender}@example.com");
    let first_request = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": username, "email": email, "password": password})
                    .to_string(),
            ))
            .expect("first bootstrap request"),
    );
    let second_request = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": contender, "email": contender_email, "password": password})
                    .to_string(),
            ))
            .expect("second concurrent bootstrap request"),
    );
    let (first_response, second_response) = tokio::join!(first_request, second_request);
    let first_response = first_response.expect("first bootstrap response");
    let second_response = second_response.expect("second bootstrap response");
    assert!(
        (first_response.status() == StatusCode::CREATED
            && second_response.status() == StatusCode::CONFLICT)
            || (first_response.status() == StatusCode::CONFLICT
                && second_response.status() == StatusCode::CREATED),
        "bootstrap statuses: {} and {}",
        first_response.status(),
        second_response.status()
    );
    let username = if first_response.status() == StatusCode::CREATED {
        let response = http::json_body(first_response).await;
        assert_eq!(response["id"], 1);
        assert_eq!(response["role"], "owner");
        username
    } else {
        let response = http::json_body(second_response).await;
        assert_eq!(response["id"], 1);
        assert_eq!(response["role"], "owner");
        contender.clone()
    };

    // #279：初始化完成后状态端点退化为通用 404，不再向匿名调用者确认实例已初始化。
    // 端点语义的完整断言在 tests/bootstrap_invariant.rs。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("initialized status request"),
        )
        .await
        .expect("initialized status response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(http::json_body(response).await["code"], "not_found");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/audit")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("audit request"),
        )
        .await
        .expect("audit response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(http::json_body(response).await.is_array());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("operator-{username}"),
                        "email": format!("operator-{username}@example.com"),
                        "password": password,
                        "role": "admin"
                    })
                    .to_string(),
                ))
                .expect("create admin request"),
        )
        .await
        .expect("create admin response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("list admins request"),
        )
        .await
        .expect("list admins response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        http::json_body(response)
            .await
            .as_array()
            .is_some_and(|admins| admins.len() >= 2)
    );

    let user_email = format!("managed-{username}@example.com");
    let user_username = format!("managed-{username}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": user_username, "email": user_email, "password": password}).to_string(),
                ))
                .expect("user registration request"),
        )
        .await
        .expect("user registration response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
    );

    let public_registration_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2",
    )
    .bind(&user_username)
    .bind(&user_email)
    .fetch_one(&database)
    .await
    .expect("check failed public registration");
    assert_eq!(public_registration_count, 0);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": user_username,
                        "email": user_email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = http::json_body(response).await;
    let user_id = user["id"].as_i64().expect("numeric user id");
    assert_eq!(user["role"], "user");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("list users request"),
        )
        .await
        .expect("list users response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        http::json_body(response)
            .await
            .as_array()
            .is_some_and(|users| users.iter().any(|user| user["id"] == user_id))
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/disabled"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("disable user request"),
        )
        .await
        .expect("disable user response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": format!("second-{username}"), "email": "invalid", "password": password})
                        .to_string(),
                ))
                .expect("second bootstrap request"),
        )
        .await
        .expect("second bootstrap response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username IN ($1, $2, $3)")
        .bind(&username)
        .bind(&contender)
        .bind(format!("operator-{username}"))
        .execute(&database)
        .await
        .expect("cleanup privileged users");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&user_email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
