use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::auth_factors::{crypto::decrypt_totp_secret, repository};
use chenxing_auth::users::avatar_image::{MAX_UPLOAD_BYTES, MIN_SOURCE_EDGE, STORED_EDGE};
use chenxing_auth::{api, config::Config, state::AppState};
use image::{ImageFormat, Rgba, RgbaImage};
use serde_json::Value;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const ADMIN_TOKEN: &str = "user-avatar-admin-token";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("user_avatar_api", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-session-ui-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, "user_avatar_api").await;
    db_isolation::isolate_user_ids(&database, "user_avatar_api").await;
    (router, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie")
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn csrf(cookies: &str) -> String {
    cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned()
}

async fn register(router: &Router, username: &str, email: &str, password: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "email": email, "password": password})
                        .to_string(),
                ))
                .expect("register request"),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn login(
    router: &Router,
    database: &chenxing_auth::sqlx::PgPool,
    identifier: &str,
    email: &str,
    password: &str,
) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": identifier, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    if response.status() == StatusCode::ACCEPTED {
        let pending_cookie = cookies(&response);
        let pending = json(response).await;
        if pending["status"] == "factor_required" {
            let code = current_totp_code(database, email).await;
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "identifier": identifier,
                                "password": password,
                                "totp_code": code
                            })
                            .to_string(),
                        ))
                        .expect("factor login request"),
                )
                .await
                .expect("factor login response");
            assert_eq!(response.status(), StatusCode::OK);
            let cookie_header = cookies(&response);
            let csrf_token = csrf(&cookie_header);
            return (cookie_header, csrf_token);
        }
        assert!(pending.get("login_ticket").is_none());
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/totp/setup")
                    .header("content-type", "application/json")
                    .header("cookie", &pending_cookie)
                    .body(Body::from(serde_json::json!({}).to_string()))
                    .expect("TOTP setup request"),
            )
            .await
            .expect("TOTP setup response");
        assert_eq!(response.status(), StatusCode::OK);
        let setup = json(response).await;
        let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/totp/setup/confirm")
                    .header("content-type", "application/json")
                    .header("cookie", &pending_cookie)
                    .body(Body::from(
                        serde_json::json!({
                            "code": totp.generate_current().expect("TOTP code")
                        })
                        .to_string(),
                    ))
                    .expect("TOTP confirmation request"),
            )
            .await
            .expect("TOTP confirmation response");
        assert_eq!(response.status(), StatusCode::OK);
        let cookie_header = cookies(&response);
        let csrf_token = csrf(&cookie_header);
        return (cookie_header, csrf_token);
    }
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_header = cookies(&response);
    let csrf_token = csrf(&cookie_header);
    (cookie_header, csrf_token)
}

async fn current_totp_code(database: &chenxing_auth::sqlx::PgPool, email: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    totp_code_at(database, email, now).await
}

async fn totp_code_at(
    database: &chenxing_auth::sqlx::PgPool,
    email: &str,
    timestamp: u64,
) -> String {
    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(database)
        .await
        .expect("user lookup");
    let encrypted = repository::find_totp_secret(database, user_id.0)
        .await
        .expect("TOTP lookup")
        .expect("TOTP factor");
    let secret = decrypt_totp_secret(&[0_u8; 32], &encrypted).expect("TOTP secret");
    // TOTP::new 按值接收 Vec<u8>，只能交出一份拷贝；
    // totp-rs 开启了 zeroize feature，TOTP 自身会在 drop 时清零该副本。
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        None,
        String::new(),
    )
    .expect("TOTP")
    .generate(timestamp)
}

/// 带逐像素噪声的 PNG：平坦色块会被压到几百字节，无法验证「重编码收敛存储」。
fn png_fixture(width: u32, height: u32) -> Vec<u8> {
    let mut image = RgbaImage::new(width, height);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        // u32 乘法在 debug 下会溢出 panic，整条混合链必须显式 wrapping。
        let noise = (x
            .wrapping_mul(2654435761)
            .wrapping_add(y.wrapping_mul(40503))
            % 251) as u8;
        *pixel = Rgba([noise, noise.wrapping_mul(3), noise.wrapping_add(97), 255]);
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
        .expect("fixture encodes");
    bytes
}

async fn put_avatar(
    router: &Router,
    cookies: &str,
    csrf: &str,
    body: Vec<u8>,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/auth/me/avatar")
                .header("cookie", cookies)
                .header("x-csrf-token", csrf)
                .header("content-type", "image/png")
                .body(Body::from(body))
                .expect("avatar upload request"),
        )
        .await
        .expect("avatar upload response")
}

#[tokio::test]
async fn avatar_upload_re_encodes_and_bounds_storage() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("avatar-{suffix}@example.com");
    let username = format!("avatar-{suffix}");
    register(&router, &username, &email, "correct horse battery").await;
    let (cookies, csrf) = login(
        &router,
        &database,
        &username,
        &email,
        "correct horse battery",
    )
    .await;

    let upload = png_fixture(900, 700);
    let response = put_avatar(&router, &cookies, &csrf, upload.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let profile = json(response).await;
    assert!(profile["avatar_updated_at"].is_string());

    let (stored, mime): (Vec<u8>, String) = chenxing_auth::sqlx::query_as(
        "SELECT avatar_data, avatar_mime FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_one(&database)
    .await
    .expect("stored avatar");

    assert_eq!(mime, "image/jpeg");
    assert_eq!(
        image::guess_format(&stored).expect("stored format"),
        ImageFormat::Jpeg,
        "落库字节必须是重编码结果，不能是上传的 PNG"
    );
    let decoded = image::load_from_memory(&stored).expect("stored decodes");
    assert_eq!(
        (decoded.width(), decoded.height()),
        (STORED_EDGE, STORED_EDGE)
    );
    assert!(
        stored.len() < upload.len() / 4,
        "重编码必须收敛存储：落库 {} vs 上传 {}",
        stored.len(),
        upload.len()
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me/avatar")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("avatar fetch request"),
        )
        .await
        .expect("avatar fetch response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/jpeg");
    // 响应随会话变化，任何共享缓存留存它都等于跨用户泄露。
    assert_eq!(response.headers()["cache-control"], "private, max-age=300");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn avatar_mutations_require_session_and_csrf() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("avatar-csrf-{suffix}@example.com");
    let username = format!("avatar-csrf-{suffix}");
    register(&router, &username, &email, "correct horse battery").await;
    let (cookies, csrf) = login(
        &router,
        &database,
        &username,
        &email,
        "correct horse battery",
    )
    .await;
    let upload = png_fixture(400, 400);

    // 无会话
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/auth/me/avatar")
                .header("content-type", "image/png")
                .body(Body::from(upload.clone()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 有会话但缺 CSRF 头
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/auth/me/avatar")
                .header("cookie", &cookies)
                .header("content-type", "image/png")
                .body(Body::from(upload.clone()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // CSRF 头与 Cookie 不匹配
    let response = put_avatar(&router, &cookies, "forged-token", upload.clone()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // DELETE 受同一套保护
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/me/avatar")
                .header("cookie", &cookies)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 三者齐备才通过
    assert_eq!(
        put_avatar(&router, &cookies, &csrf, upload).await.status(),
        StatusCode::OK
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn server_independently_rejects_invalid_avatars() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("avatar-reject-{suffix}@example.com");
    let username = format!("avatar-reject-{suffix}");
    register(&router, &username, &email, "correct horse battery").await;
    let (cookies, csrf) = login(
        &router,
        &database,
        &username,
        &email,
        "correct horse battery",
    )
    .await;

    // 尺寸下限：前端预检可被绕过，服务端必须独立复核。
    let response = put_avatar(
        &router,
        &cookies,
        &csrf,
        png_fixture(MIN_SOURCE_EDGE - 1, 400),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "avatar_too_small");

    // 格式白名单按魔数判定，不看 Content-Type。
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&[0u8; 512]);
    let response = put_avatar(&router, &cookies, &csrf, gif).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "avatar_unsupported_format");

    // 合法魔数 + 垃圾载荷：解码必须失败且不 panic。
    let mut forged = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    forged.extend_from_slice(&[0xab; 512]);
    let response = put_avatar(&router, &cookies, &csrf, forged).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "avatar_undecodable");

    // 超出体积上限由中间件在进入处理器前拦下。
    let response = put_avatar(&router, &cookies, &csrf, vec![0u8; MAX_UPLOAD_BYTES + 1]).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 全部失败后仍无头像残留。
    let leftover: Option<Vec<u8>> =
        chenxing_auth::sqlx::query_scalar("SELECT avatar_data FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&database)
            .await
            .expect("avatar lookup");
    assert!(leftover.is_none());

    let _ = std::fs::remove_dir_all(key_directory);
}
