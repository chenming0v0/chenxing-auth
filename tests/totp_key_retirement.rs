//! #258 回归测试：`AUTH_ENCRYPTION_KEYS` 里的 kid 退役后的 TOTP 恢复路径。
//!
//! 场景：账号在密钥环 A（active kid `k1`）下注册 TOTP，随后运维轮换密钥并把 `k1`
//! 移出密钥环。此时密文永久不可解，而懒迁移挂在「一次成功验证之后」，验证本身
//! 已经失败——修复前用户被永久锁死且没有任何出口。
//!
//! 本文件锁定四条不变量：
//! 1. 不可解密不再伪装成「验证码错误」：503 `factor_key_unavailable` 而不是 401。
//! 2. 这条路径不烧失败额度：连续触发后正常的密码登录仍然可用，不会被限流。
//! 3. Owner 可以重置因子，账号回到 `factor_setup_required` 并能重新绑定。
//! 4. 重置权限是 Owner 专属的 `manage_auth_factors`，Admin 会被 403 拒绝。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    config::{AuthEncryptionKey, AuthEncryptionKeyRing, Config},
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

const ADMIN_TOKEN: &str = "totp-key-retirement-admin-token";

fn ring(active_kid: &str, entries: &[(&str, [u8; 32])]) -> AuthEncryptionKeyRing {
    AuthEncryptionKeyRing::from_entries(
        active_kid.to_owned(),
        entries
            .iter()
            .map(|(kid, key)| ((*kid).to_owned(), AuthEncryptionKey::new(*key)))
            .collect(),
    )
    .expect("test key ring")
}

struct Fixture {
    database: chenxing_auth::sqlx::PgPool,
    redis_url: String,
    key_directory: std::path::PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let database = db_isolation::isolated_pool("totp_key_retirement", &database_url).await;
        Self {
            database,
            redis_url,
            key_directory: key_directory::isolated_key_directory("totp-key-retirement"),
        }
    }

    /// 用给定密钥环构建一个共享同一套 PostgreSQL / Redis 的 router。
    /// 「轮换密钥」在测试里就等于换一个密钥环重建 router。
    async fn router(&self, keys: AuthEncryptionKeyRing) -> Router {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let mut config = Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            "http://127.0.0.1:3000".to_owned(),
            database_url,
            self.redis_url.clone(),
            3600,
        )
        .expect("test configuration");
        config.admin_token = ADMIN_TOKEN.to_owned();
        config.cookie_secure = false;
        config.key_directory = self.key_directory.to_string_lossy().into_owned();
        config.auth_encryption_keys = keys;
        api::router(
            AppState::new_with_pool(config, self.database.clone())
                .await
                .expect("test state"),
        )
    }

    /// 直接落一条会话，返回 (Cookie 头, CSRF 令牌)。
    /// 会话载荷用同一个密钥环加密，否则轮换后的 router 读不出它。
    async fn browser_session(&self, keys: AuthEncryptionKeyRing, user_id: i64) -> (String, String) {
        let redis = redis::Client::open(self.redis_url.as_str()).expect("session Redis");
        let store = SessionStore::with_metadata_and_key_ring(redis, self.database.clone(), keys);
        let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
            .expect("browser session");
        store
            .save(&mut session, std::time::Duration::from_secs(3600))
            .await
            .expect("save browser session");
        (
            format!(
                "{}={}; {}={}",
                cookies::session_cookie_name(false),
                session.token,
                cookies::csrf_cookie_name(false),
                session.csrf_token
            ),
            session.csrf_token,
        )
    }

    fn cleanup(self) {
        let _ = std::fs::remove_dir_all(self.key_directory);
    }
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

fn pending_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn post(router: &Router, uri: &str, payload: serde_json::Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

async fn post_with_cookie(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
    cookie: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

async fn bootstrap_owner(router: &Router, suffix: &str) {
    let response = post(
        router,
        "/api/v1/admin/bootstrap",
        serde_json::json!({
            "username": format!("retire-owner-{suffix}"),
            "email": format!("retire-owner-{suffix}@example.com"),
            "password": "correct horse battery",
        }),
    )
    .await;
    assert!(matches!(
        response.status(),
        StatusCode::CREATED | StatusCode::CONFLICT
    ));
}

async fn create_user(
    router: &Router,
    username: &str,
    email: &str,
    password: &str,
    role: &str,
) -> i64 {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "role": role,
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["id"]
        .as_i64()
        .expect("created user id")
}

/// 完成一次 TOTP 首绑，返回生成器。密文由该 router 的 active kid 加密。
async fn enroll_totp(router: &Router, username: &str, password: &str) -> TOTP {
    let login = post(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login.status(), StatusCode::ACCEPTED);
    let cookie = pending_cookie(&login);
    assert_eq!(json_body(login).await["status"], "factor_setup_required");
    let setup_response = post_with_cookie(
        router,
        "/api/v1/auth/totp/setup",
        serde_json::json!({}),
        &cookie,
    )
    .await;
    let setup = json_body(setup_response).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    assert_eq!(
        post_with_cookie(
            router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({"code": totp.generate_current().expect("enrollment code")}),
            &cookie,
        )
        .await
        .status(),
        StatusCode::OK
    );
    totp
}

#[tokio::test]
// #258：kid 退役后的登录必须与「验证码错误」区分，且不消耗失败额度。
async fn retired_encryption_kid_is_reported_as_unavailable_without_burning_quota() {
    let fixture = Fixture::new().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let old_ring = ring("k1", &[("k1", [1; 32]), ("k2", [2; 32])]);
    // k1 已从密钥环移除：这正是运维「轮换后退役旧 key」的最终状态。
    let retired_ring = ring("k2", &[("k2", [2; 32])]);

    let before = fixture.router(old_ring).await;
    bootstrap_owner(&before, &suffix).await;
    db_isolation::isolate_user_ids(&fixture.database, "totp_key_retirement").await;
    let username = format!("retire-{suffix}");
    let email = format!("{username}@example.com");
    let password = "correct horse battery";
    create_user(&before, &username, &email, password, "user").await;
    let totp = enroll_totp(&before, &username, password).await;

    let after = fixture.router(retired_ring.clone()).await;

    // 1. 正确的验证码也读不出种子：503 而不是 401，错误码明确指向密钥不可用。
    let login = post(
        &after,
        "/api/v1/auth/login",
        serde_json::json!({
            "identifier": username,
            "password": password,
            "totp_code": totp.generate_current().expect("valid code"),
        }),
    )
    .await;
    assert_eq!(
        login.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an unreadable secret must not be reported as an invalid code"
    );
    let body = json_body(login).await;
    assert_eq!(body["code"], "factor_key_unavailable");
    // 响应不得泄漏 kid 或种子。
    let rendered = body.to_string();
    assert!(!rendered.contains("k1"));
    assert!(!rendered.contains("k2"));

    // 2. 反复触发也不烧失败额度：账户维度阈值是 10，这里触发 12 次。
    for attempt in 0..12 {
        let response = post(
            &after,
            "/api/v1/auth/login",
            serde_json::json!({
                "identifier": username,
                "password": password,
                "totp_code": "000000",
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "attempt {attempt} must stay a key-availability failure, not a rate limit"
        );
    }
    // 不带 totp_code 的密码登录仍然可用：账号没有被推向限流。
    let pending = post(
        &after,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(
        pending.status(),
        StatusCode::ACCEPTED,
        "the account must not be rate limited by a server-side key problem"
    );

    // 3. 通过 login ticket 的 TOTP 端点同样返回 503。
    let ticket = pending_cookie(&pending);
    assert_eq!(json_body(pending).await["status"], "factor_required");
    let response = post_with_cookie(
        &after,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": totp.generate_current().expect("valid code")}),
        &ticket,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(response).await["code"], "factor_key_unavailable");

    fixture.cleanup();
}

#[tokio::test]
// #258：Owner 重置因子后账号恢复可用；权限是 Owner 专属，Admin 被拒。
async fn owner_can_reset_a_locked_totp_factor_and_admin_cannot() {
    let fixture = Fixture::new().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let old_ring = ring("k1", &[("k1", [1; 32]), ("k2", [2; 32])]);
    let retired_ring = ring("k2", &[("k2", [2; 32])]);

    let before = fixture.router(old_ring).await;
    bootstrap_owner(&before, &suffix).await;
    db_isolation::isolate_user_ids(&fixture.database, "totp_key_retirement").await;
    let username = format!("locked-{suffix}");
    let email = format!("{username}@example.com");
    let password = "correct horse battery";
    let user_id = create_user(&before, &username, &email, password, "user").await;
    let _totp = enroll_totp(&before, &username, password).await;

    let after = fixture.router(retired_ring.clone()).await;
    let owner_id: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'owner' ORDER BY id ASC LIMIT 1",
    )
    .fetch_one(&fixture.database)
    .await
    .expect("owner id");
    let (owner_cookie, owner_csrf) = fixture
        .browser_session(retired_ring.clone(), owner_id)
        .await;

    // 因子状态端点如实报告「密文不可读」，且不返回 kid 或种子。
    let status = after
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/admin/users/{user_id}/auth-factors"))
                .header("cookie", &owner_cookie)
                .body(Body::empty())
                .expect("factor status request"),
        )
        .await
        .expect("factor status response");
    assert_eq!(status.status(), StatusCode::OK);
    let status = json_body(status).await;
    assert_eq!(status["totp"]["key_state"], "unavailable");
    assert_eq!(status["totp"]["readable"], false);
    assert!(status["totp"].get("kid").is_none());

    // 密钥健康度端点在退役旧 key 之后能数出被锁死的账号。
    let health = after
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/auth-factors/key-health")
                .header("cookie", &owner_cookie)
                .body(Body::empty())
                .expect("key health request"),
        )
        .await
        .expect("key health response");
    assert_eq!(health.status(), StatusCode::OK);
    let health = json_body(health).await;
    assert!(
        health["unavailable"].as_i64().expect("unavailable count") >= 1,
        "key health must surface unreadable secrets: {health}"
    );

    // Admin 不得重置他人的因子：这是 Owner 专属的 manage_auth_factors。
    let admin_id = create_user(
        &after,
        &format!("retire-admin-{suffix}"),
        &format!("retire-admin-{suffix}@example.com"),
        password,
        "admin",
    )
    .await;
    let (admin_cookie, admin_csrf) = fixture
        .browser_session(retired_ring.clone(), admin_id)
        .await;
    let denied = after
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{user_id}/auth-factors/totp"))
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .expect("admin reset request"),
        )
        .await
        .expect("admin reset response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(denied).await["code"], "admin_forbidden");

    // 缺少 X-CSRF-Token 的浏览器写操作必须被拒，即使调用者是 Owner。
    let without_csrf = after
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{user_id}/auth-factors/totp"))
                .header("cookie", &owner_cookie)
                .body(Body::empty())
                .expect("reset without CSRF request"),
        )
        .await
        .expect("reset without CSRF response");
    assert_eq!(without_csrf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(without_csrf).await["code"], "csrf_invalid");

    // Owner 带齐 Session Cookie、CSRF Cookie 与头部：重置成功。
    let reset = after
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{user_id}/auth-factors/totp"))
                .header("cookie", &owner_cookie)
                .header("x-csrf-token", &owner_csrf)
                .body(Body::empty())
                .expect("owner reset request"),
        )
        .await
        .expect("owner reset response");
    assert_eq!(reset.status(), StatusCode::OK);
    let reset = json_body(reset).await;
    assert_eq!(reset["previous_key_state"], "unavailable");
    assert_eq!(reset["sessions_revoked"], true);

    // 重置后账号回到「无因子」，可以重新绑定并完成登录。
    let totp = enroll_totp(&after, &username, password).await;
    let login = post(
        &after,
        "/api/v1/auth/login",
        serde_json::json!({
            "identifier": username,
            "password": password,
            "totp_code": totp.generate_current().expect("new code"),
        }),
    )
    .await;
    assert_eq!(
        login.status(),
        StatusCode::OK,
        "the account must be usable again after re-enrollment"
    );

    // 因子已经不存在：重复重置返回 404，而不是伪装成又一次成功。
    let repeat = after
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{admin_id}/auth-factors/totp"))
                .header("cookie", &owner_cookie)
                .header("x-csrf-token", &owner_csrf)
                .body(Body::empty())
                .expect("repeat reset request"),
        )
        .await
        .expect("repeat reset response");
    assert_eq!(repeat.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(repeat).await["code"], "totp_factor_not_found");

    // 重置动作必须留下可检索的审计记录，且元数据不含 kid 或种子。
    let audit: Option<serde_json::Value> = chenxing_auth::sqlx::query_scalar(
        "SELECT metadata FROM audit_events
         WHERE action = 'user_totp_factor_reset' AND resource_id = $1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(user_id.to_string())
    .fetch_optional(&fixture.database)
    .await
    .expect("audit lookup");
    let audit = audit.expect("factor reset must be audited");
    assert_eq!(audit["previous_key_state"], "unavailable");
    assert_eq!(audit["method"], "totp");
    let rendered = audit.to_string();
    assert!(!rendered.contains("k1"));
    assert!(!rendered.contains("secret"));

    fixture.cleanup();
}
