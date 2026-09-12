use axum::http::StatusCode;
use chenxing_auth::auth_limiter::FailureDimension;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::http;

use super::passkey_auth::{
    ExistingChallengeBehavior, assert_start_reserves_one_challenge, bogus_registration_credential,
    cleanup_user, create_user, exhaust_ticket_failures, login_ticket, mfa_failure_reasons,
    post_with_cookie, setup, ticket_failure_limit, user_id_for_email,
};

#[tokio::test]
async fn passkey_registration_start_returns_creation_challenge_for_login_ticket() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert!(body["publicKey"]["challenge"].as_str().is_some());
    assert!(body["publicKey"]["rp"]["id"].as_str().is_some());
    assert_eq!(
        body["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    assert!(body["session_id"].is_null());

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": {
                "id": "",
                "rawId": "",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "type": "public-key"
            }
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_registration_starts_reserve_one_challenge_without_burning_failures() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;
    let pending_key = format!("chenxing:auth:passkey-registration:{}", ticket.0);

    assert_start_reserves_one_challenge(
        &router,
        "/api/v1/auth/passkeys/register/start",
        &ticket,
        &pending_key,
        ExistingChallengeBehavior::Reject,
    )
    .await;
    assert!(
        mfa_failure_reasons(&database, user_id).await.is_empty(),
        "rejected registration starts must not be recorded as failures"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_registration_uses_updated_settings_and_keeps_start_snapshot() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let old_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "Old RP",
        "rp_id": "example.com",
        "user_verification": "required",
        "authenticator_attachment": "platform",
        "allow_insecure_origin": false,
        "allowed_origins": ["https://login.example.com"]
    });
    chenxing_auth::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('passkey', $1, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(old_setting.to_string())
    .execute(&database)
    .await
    .expect("old passkey setting");

    let ticket = login_ticket(&state, &database, &email).await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = http::json_body(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "Old RP");
    assert_eq!(challenge["publicKey"]["rp"]["id"], "example.com");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );

    let new_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "New RP",
        "rp_id": "example.com",
        "user_verification": "preferred",
        "authenticator_attachment": "cross_platform",
        "allow_insecure_origin": true,
        "allowed_origins": ["http://new.example.com"]
    });
    chenxing_auth::sqlx::query(
        "UPDATE app_settings SET setting_value = $1, updated_at = NOW()
         WHERE setting_key = 'passkey'",
    )
    .bind(new_setting.to_string())
    .execute(&database)
    .await
    .expect("new passkey setting");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!("chenxing:auth:passkey-registration:{}", ticket.0))
            .await
            .expect("registration snapshot"),
    )
    .expect("registration snapshot JSON");
    assert_eq!(pending["settings"]["rp_name"], "Old RP");
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["https://login.example.com"])
    );

    let second_ticket = login_ticket(&state, &database, &email).await;
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &second_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = http::json_body(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "New RP");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "cross-platform"
    );
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!(
                "chenxing:auth:passkey-registration:{}",
                second_ticket.0
            ))
            .await
            .expect("updated registration snapshot"),
    )
    .expect("updated registration snapshot JSON");
    assert_eq!(pending["settings"]["allow_insecure_origin"], true);
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["http://new.example.com"])
    );

    chenxing_auth::sqlx::query("DELETE FROM app_settings WHERE setting_key = 'passkey'")
        .execute(&database)
        .await
        .expect("passkey setting cleanup");
    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _: usize = connection
        .del(format!("chenxing:auth:passkey-registration:{}", ticket.0))
        .await
        .expect("old snapshot cleanup");
    let _: usize = connection
        .del(format!(
            "chenxing:auth:passkey-registration:{}",
            second_ticket.0
        ))
        .await
        .expect("new snapshot cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_finish_failures_are_rate_limited_and_invalidate_the_ticket() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    let ticket = login_ticket(&state, &database, &email).await;

    // 阈值内的失败仍然按“凭据无效”处理，不会被限流提前拒绝。
    let statuses = exhaust_ticket_failures(&router, &ticket).await;
    assert!(
        statuses
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED),
        "expected every in-window failure to stay 401, got {statuses:?}"
    );

    // ticket 维度达阈值后 ticket 已被失效，后续请求连挂起状态都不复存在。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": bogus_registration_credential()
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(response).await["code"],
        "invalid_login_ticket"
    );

    // mfa_failure 审计事件必须带真实 actor_id，而不是写死的 anonymous。
    let events = mfa_failure_reasons(&database, user_id).await;
    assert_eq!(events.len(), ticket_failure_limit());
    assert!(
        events.iter().all(|(actor_type, _)| actor_type == "user"),
        "expected user actor_type on every mfa_failure event, got {events:?}"
    );
    let reasons: Vec<&str> = events.iter().map(|(_, reason)| reason.as_str()).collect();
    assert_eq!(
        reasons.last().copied(),
        Some("passkey_rate_limited"),
        "expected the threshold failure to be recorded as rate limited, got {reasons:?}"
    );
    assert!(
        reasons[..ticket_failure_limit() - 1]
            .iter()
            .all(|reason| *reason == "passkey_invalid"),
        "expected sub-threshold failures to stay passkey_invalid, got {reasons:?}"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_start_endpoints_reject_before_touching_passkey_storage() {
    let (router, state, database, key_directory, email) = setup().await;
    let _username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;

    let other_email = format!("passkey-other-{}@example.com", Uuid::new_v4().simple());
    let _other_username = create_user(&router, &other_email).await;
    let other_user_id = user_id_for_email(&database, &other_email).await;

    // 账号维度上限高于单个 ticket 上限，需要多个 ticket 才能把账号额度耗尽。
    // spare_ticket 必须在耗尽之前签发：账号被限流后 /auth/login 自身也会被拒绝。
    let tickets_to_exhaust_account =
        (FailureDimension::Account.limit() as usize).div_ceil(ticket_failure_limit());
    let mut burn_tickets = Vec::new();
    for _ in 0..tickets_to_exhaust_account {
        burn_tickets.push(login_ticket(&state, &database, &email).await);
    }
    let spare_ticket = login_ticket(&state, &database, &email).await;
    let other_ticket = login_ticket(&state, &database, &other_email).await;

    for ticket in &burn_tickets {
        exhaust_ticket_failures(&router, ticket).await;
    }

    // 账号维度耗尽后，challenge 端点必须在 list_passkeys 之前就拒绝。该账号没有任何
    // Passkey，若限流检查在数据库查询之后才生效，这里会退化成 400 invalid_login_ticket。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(http::json_body(response).await["code"], "invalid_factor");

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 限流按账号隔离：另一个账号的成功路径不受这些失败影响。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &other_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        mfa_failure_reasons(&database, other_user_id)
            .await
            .is_empty(),
        "unrelated account must not accumulate mfa_failure events"
    );

    cleanup_user(&database, user_id).await;
    cleanup_user(&database, other_user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}
