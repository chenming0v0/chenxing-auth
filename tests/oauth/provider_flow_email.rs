use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::settings::EmailPolicySetting;
use tower::ServiceExt;

use crate::http;

use super::provider_flow::{mock_server, run_external_login, set_cookie_header_optional, setup};

async fn set_email_policy(
    database: &chenxing_auth::sqlx::PgPool,
    alias_restriction_enabled: bool,
    allowed_domains: &[&str],
) {
    let policy = EmailPolicySetting {
        whitelist_enabled: true,
        alias_restriction_enabled,
        allowed_domains: allowed_domains
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect(),
    }
    .validate()
    .expect("valid email policy fixture");
    chenxing_auth::settings::repository::set_email_policy(database, &policy)
        .await
        .expect("persist email policy");
}

async fn external_registration_counts(
    database: &chenxing_auth::sqlx::PgPool,
    subject: &str,
    email: &str,
) -> (i64, i64) {
    chenxing_auth::sqlx::query_as(
        "SELECT
             (SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1),
             (SELECT COUNT(*) FROM users WHERE canonical_email = $2)",
    )
    .bind(subject)
    .bind(email)
    .fetch_one(database)
    .await
    .expect("count external registration rows")
}

#[tokio::test]
async fn external_registration_rejects_domain_and_alias_without_partial_writes() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    set_email_policy(&database, true, &["corp.example"]).await;

    for (email, reason) in [
        ("person@other.example", "domain outside whitelist"),
        ("person+alias@corp.example", "alias address"),
    ] {
        *mock_state.user_email.lock().await = email.to_owned();
        let response = run_external_login(&router, &slug).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            http::location(&response).contains("external_error=oauth_login_failed"),
            "{reason} must be rejected without exposing policy details: {}",
            http::location(&response)
        );
        assert!(
            set_cookie_header_optional(&response, "chenxing_session=").is_none(),
            "{reason} must not create a browser session"
        );
        assert_eq!(
            external_registration_counts(&database, &external_subject, email).await,
            (0, 0),
            "{reason} must leave neither a user nor an external identity"
        );
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn external_registration_allows_a_whitelisted_non_alias_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let allowed_email = "person@corp.example";
    *mock_state.user_email.lock().await = allowed_email.to_owned();
    let (router, database, key_directory, slug) = setup(mock).await;
    set_email_policy(&database, true, &["corp.example"]).await;

    let response = run_external_login(&router, &slug).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(http::location(&response).contains("external=success"));
    assert_eq!(
        external_registration_counts(&database, &external_subject, allowed_email).await,
        (1, 1)
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn existing_external_identity_ignores_later_email_policy_changes() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;

    let first = run_external_login(&router, &slug).await;
    assert!(http::location(&first).contains("external=success"));
    let original_user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT user_id FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("load initially bound external user");

    set_email_policy(&database, true, &["corp.example"]).await;
    let second = run_external_login(&router, &slug).await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&second).contains("external=success"),
        "an existing identity must not be re-evaluated as a new registration"
    );
    let rebound_user_ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT user_id FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_all(&database)
    .await
    .expect("reload external identity rows");
    assert_eq!(rebound_user_ids, vec![original_user_id]);
    assert_eq!(
        external_registration_counts(&database, &external_subject, &external_email).await,
        (1, 1)
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #261：未验证邮箱既不能登录，也不能自动建号。
///
/// 覆盖三种真实的 IdP 行为：完全不返回 claim、返回 false、返回非 bool 值。
/// 过去只有第二种会被拦下，第一种直接放行建号，第三种取决于路径细节。
#[tokio::test]
async fn custom_provider_rejects_unverified_external_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;

    for claim in [
        serde_json::Value::Null,
        serde_json::json!(false),
        serde_json::json!("true"),
        serde_json::json!(1),
    ] {
        *mock_state.email_verified.lock().await = claim.clone();
        let response = run_external_login(&router, &slug).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let redirect = http::location(&response);
        assert!(
            redirect.contains("external_error=oauth_email_unverified"),
            "email_verified={claim} 必须被拒绝，实际跳转: {redirect}"
        );
        assert!(
            set_cookie_header_optional(&response, "chenxing_session=").is_none(),
            "被拒绝的外部登录不得签发会话 Cookie"
        );

        let identities: (i64,) = chenxing_auth::sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
        )
        .bind(&external_subject)
        .fetch_one(&database)
        .await
        .expect("identity count");
        assert_eq!(identities.0, 0, "email_verified={claim} 不得建立外部身份");
        let users: (i64,) =
            chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
                .bind(&external_email)
                .fetch_one(&database)
                .await
                .expect("user count");
        assert_eq!(users.0, 0, "email_verified={claim} 不得自动建号");
    }

    // 同一个 provider 在 claim 变成 true 之后必须能正常登录，
    // 证明拒绝来自 claim 取值而不是配置被误伤。
    *mock_state.email_verified.lock().await = serde_json::json!(true);
    let response = run_external_login(&router, &slug).await;
    assert!(http::location(&response).contains("external=success"));
    let users: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("user count");
    assert_eq!(users.0, 1);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 存量行的 email_verified_claim 可能是 NULL。这类 provider 不能被启用，
/// 已经启用的（迁移前写入的）也不能放行外部登录。
#[tokio::test]
async fn legacy_provider_without_email_verified_claim_cannot_enable_or_login() {
    let (mock, _mock_state) = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;

    // 绕过应用层写出一个存量形态的行：claim 为 NULL 且处于启用状态。
    // CHECK 约束禁止 active + NULL 的组合，所以先停用再清空 claim，
    // 最后直接改 status，模拟迁移前留下的数据。
    chenxing_auth::sqlx::query(
        "UPDATE oauth_providers SET status = 'disabled', email_verified_claim = NULL WHERE slug = $1",
    )
    .bind(&slug)
    .execute(&database)
    .await
    .expect("clear email_verified_claim");

    let (expected_version,): (i64,) =
        chenxing_auth::sqlx::query_as("SELECT state_version FROM oauth_providers WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&database)
            .await
            .expect("provider version");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}/enable"))
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "expected_version": expected_version }).to_string(),
                ))
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let status: (String,) =
        chenxing_auth::sqlx::query_as("SELECT status FROM oauth_providers WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&database)
            .await
            .expect("provider status");
    assert_eq!(status.0, "disabled", "启用必须被拒绝且不改动存储状态");

    // 迁移前写入的 active + NULL 行：登录入口必须直接拒绝。
    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_providers DROP CONSTRAINT oauth_providers_active_requires_email_verified_claim",
    )
    .execute(&database)
    .await
    .expect("drop constraint for legacy row simulation");
    chenxing_auth::sqlx::query("UPDATE oauth_providers SET status = 'active' WHERE slug = $1")
        .bind(&slug)
        .execute(&database)
        .await
        .expect("force legacy active row");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = http::location(&response);
    assert!(
        redirect.contains("external_error=oauth_provider_not_found"),
        "缺少 claim 的 provider 不得跳转外部 IdP，实际: {redirect}"
    );
    assert!(
        !redirect.starts_with("http"),
        "不得把用户送到外部 IdP: {redirect}"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
