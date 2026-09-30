//! Frozen v2 boundary: ordinary OAuth AT -> product/device login assertion.
//! Device slots and local sessions belong to Go, not this service.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware::from_fn,
    routing::post,
};
use chenxing_auth::{
    api,
    oauth::{
        revocation::TokenRevocationStore,
        token::{decode_access_token, decode_userinfo_token, issue_access_token_at},
    },
    resource_services::exchange::response_boundary,
    settings::IssuerRuntime,
    sqlx,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;

use crate::http;
mod support;
use support::*;

#[tokio::test]
async fn exchange_issues_exact_v2_claims_for_each_trusted_client_package() {
    let env = setup().await;
    for (package, app) in [
        ("top.clyact", "chrome_termux"),
        ("com.termux", "termux_chrome"),
    ] {
        set_package(&env, Some(package)).await;
        let mut input = valid_body();
        input["app_kind"] = json!(app);
        input["device_id"] = json!(" 安装-ID ");
        let response = exchange(&env, Some(&env.token), input).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let body = http::json_body(response).await;
        assert_eq!(body.as_object().unwrap().len(), 6);
        assert_eq!(body["v"], 2);
        assert_eq!(body["uid"], "cltermux:42");
        assert_eq!(body["app_kind"], app);
        assert_eq!(body["device_id"], " 安装-ID ");
        for key in ["session_token", "access_token", "refresh_token", "id_token"] {
            assert!(body.get(key).is_none());
        }
        let token = body["login_ticket"].as_str().expect("login ticket");
        let header = jsonwebtoken::decode_header(token).expect("JWT header");
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let key = env
            .state
            .keys
            .verification_key_for(header.kid.as_deref().expect("kid"))
            .expect("published key");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.leeway = 0;
        validation.set_issuer(&[issuer(&env.state)]);
        validation.set_audience(&[CLIENT]);
        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .expect("signed ticket")
            .claims;
        assert_eq!(claims.as_object().unwrap().len(), 13);
        assert_eq!(claims["iss"], issuer(&env.state));
        assert_eq!(claims["sub"], env.user_id.to_string());
        assert_eq!(claims["aud"], CLIENT);
        assert_eq!(claims["v"], 2);
        assert_eq!(claims["token_use"], "cltermux_login");
        assert_eq!(claims["uid"], body["uid"]);
        assert_eq!(claims["binding_id"], env.binding_id.to_string());
        assert_eq!(claims["binding_version"], 1);
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["app_kind"], app);
        assert_eq!(claims["device_id"], body["device_id"]);
        let iat = claims["iat"].as_i64().expect("integer iat");
        let exp = claims["exp"].as_i64().expect("integer exp");
        assert_eq!(exp - iat, 300);
        let expires =
            OffsetDateTime::parse(body["expires_at"].as_str().unwrap(), &Rfc3339).unwrap();
        assert_eq!(expires.unix_timestamp(), exp);
        assert_eq!(expires.nanosecond(), 0);
        assert!(decode_access_token(&env.state.keys, &issuer(&env.state), CLIENT, token).is_err());
        assert!(decode_userinfo_token(&env.state.keys, &issuer(&env.state), token).is_err());
    }
    // Signing does not mutate AP linkage, generation or the snapshot.
    let row: (i64, Value) = sqlx::query_as(
        "SELECT generation, snapshot_json FROM resource_service_bindings WHERE id = $1",
    )
    .bind(env.binding_id)
    .fetch_one(&env.database)
    .await
    .unwrap();
    assert_eq!(row.0, 1);
    assert_eq!(row.1["fields"], json!([]));
}

#[tokio::test]
async fn exchange_rejects_missing_malformed_expired_and_revoked_access_tokens() {
    let env = setup().await;
    for token in [None, Some("not-a-token")] {
        assert_error(
            exchange(&env, token, valid_body()).await,
            StatusCode::UNAUTHORIZED,
            "invalid_chenxing_token",
        )
        .await;
    }
    let expired = issue_access_token_at(
        &env.state.keys,
        &issuer(&env.state),
        &env.user_id.to_string(),
        CLIENT,
        &["openid".to_owned(), SCOPE.to_owned()],
        60,
        OffsetDateTime::now_utc() - Duration::seconds(120),
    )
    .unwrap();
    assert_error(
        exchange(&env, Some(&expired), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
    env.state
        .revocations
        .revoke(&env.token, 3600)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
}

#[tokio::test]
async fn exchange_strictly_validates_app_device_and_metadata_before_signing() {
    let env = setup().await;
    for input in [
        json!({}),
        json!({"device_id": "id"}),
        json!({"app_kind": "chrome_termux"}),
        json!({"app_kind": "other", "device_id": "id"}),
        json!({"app_kind": null, "device_id": "id"}),
        json!({"app_kind": 2, "device_id": "id"}),
        json!({"app_kind": "chrome_termux", "device_id": null}),
        json!({"app_kind": "chrome_termux", "device_id": 1}),
        json!({"app_kind": "chrome_termux", "device_id": ""}),
        json!({"app_kind": "chrome_termux", "device_id": "x".repeat(256)}),
        json!({"app_kind": "chrome_termux", "device_id": "界".repeat(86)}),
        json!({"app_kind": "chrome_termux", "device_id": "id\n"}),
        json!({"app_kind": "chrome_termux", "device_id": "id\u{0085}"}),
        json!({"app_kind": "chrome_termux", "device_id": "id", "device_info": "界".repeat(342)}),
        json!({"app_kind": "chrome_termux", "device_id": "id", "device_info": {}}),
        json!({"app_kind": "chrome_termux", "device_id": "id", "provider": []}),
        json!({"app_kind": "chrome_termux", "device_id": "id", "package_name": "top.clyact"}),
    ] {
        assert_error(
            exchange(&env, Some(&env.token), input).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    for raw in [
        "{",
        r#"{"app_kind":"chrome_termux","app_kind":"termux_chrome","device_id":"id"}"#,
    ] {
        let response = raw_exchange(&env, raw).await;
        let expected = if raw == "{" {
            "invalid_json"
        } else {
            "invalid_request"
        };
        assert_error(response, StatusCode::BAD_REQUEST, expected).await;
    }
    for info in [Value::Null, json!("x".repeat(1024))] {
        let response = exchange(
            &env,
            Some(&env.token),
            json!({"app_kind": "chrome_termux", "device_id": "x".repeat(255), "device_info": info}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn exchange_rejects_missing_other_mismatched_and_disabled_client_declarations() {
    let env = setup().await;
    for package in [None, Some("com.other"), Some("com.termux")] {
        set_package(&env, package).await;
        assert_error(
            exchange(&env, Some(&env.token), valid_body()).await,
            StatusCode::FORBIDDEN,
            "app_not_allowed",
        )
        .await;
    }
    set_package(&env, Some("top.clyact")).await;
    sqlx::query("UPDATE oauth_clients SET status = 'disabled' WHERE client_id = $1")
        .bind(CLIENT)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "app_not_allowed",
    )
    .await;
}

#[tokio::test]
async fn exchange_client_lookup_failure_is_safe_and_fail_closed() {
    let env = setup().await;
    // Corrupt only this isolated test's declaration; never use a production DSN.
    sqlx::query("UPDATE oauth_clients SET android_asset_link = '{}'::jsonb WHERE client_id = $1")
        .bind(CLIENT)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "provider_unavailable",
    )
    .await;
}

#[tokio::test]
async fn exchange_keeps_live_scope_and_consent_revocation_gates() {
    let env = setup().await;
    let token = token_for(&env, &["openid"]);
    assert_error(
        exchange(&env, Some(&token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    )
    .await;
    sqlx::query("UPDATE oauth_clients SET scopes = '[\"openid\"]'::jsonb WHERE client_id = $1")
        .bind(CLIENT)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    )
    .await;
    grant_scopes(&env, &["openid", SCOPE]).await;
    env.state
        .consents
        .revoke_for_user(env.user_id, CLIENT)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
}

#[tokio::test]
async fn exchange_keeps_provider_allowlist_and_enabled_gates() {
    let env = setup().await;
    sqlx::query(
        "UPDATE resource_service_providers SET allowed_client_ids = ARRAY[]::text[] WHERE id = $1",
    )
    .bind(env.provider_id)
    .execute(&env.database)
    .await
    .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    )
    .await;
    // Public scope ignores its allowlist, as before; it still needs a trusted app declaration.
    sqlx::query("UPDATE resource_service_providers SET scope_access = 'public' WHERE id = $1")
        .bind(env.provider_id)
        .execute(&env.database)
        .await
        .unwrap();
    assert_eq!(
        exchange(&env, Some(&env.token), valid_body())
            .await
            .status(),
        StatusCode::OK
    );
    sqlx::query("UPDATE resource_service_providers SET enabled = FALSE WHERE id = $1")
        .bind(env.provider_id)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    )
    .await;
}

#[tokio::test]
async fn exchange_multiple_candidates_require_provider_but_v2_never_signs_other_scopes() {
    let env = setup().await;
    seed_provider(&env.database, "other", "other:access").await;
    grant_scopes(&env, &["openid", SCOPE, "other:access"]).await;
    let token = token_for(&env, &["openid", SCOPE, "other:access"]);
    assert_error(
        exchange(&env, Some(&token), valid_body()).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    for slug in ["other", "missing"] {
        let mut body = valid_body();
        body["provider"] = json!(slug);
        assert_error(
            exchange(&env, Some(&token), body).await,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        )
        .await;
    }
    let mut body = valid_body();
    body["provider"] = json!("cltermux");
    assert_eq!(
        exchange(&env, Some(&token), body).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn exchange_requires_positive_cltermux_uid_and_live_active_binding() {
    let env = setup().await;
    for uid in [
        "other:42",
        "cltermux:0",
        "cltermux:-1",
        "cltermux:+1",
        "cltermux:1.5",
        "",
    ] {
        sqlx::query("UPDATE resource_service_bindings SET uid = $2 WHERE id = $1")
            .bind(env.binding_id)
            .bind(uid)
            .execute(&env.database)
            .await
            .unwrap();
        assert_error(
            exchange(&env, Some(&env.token), valid_body()).await,
            StatusCode::FORBIDDEN,
            "account_not_linked",
        )
        .await;
    }
    sqlx::query("UPDATE resource_service_bindings SET uid = 'cltermux:42', snapshot_json = '{\"status\":\"disabled\"}'::jsonb WHERE id = $1").bind(env.binding_id).execute(&env.database).await.unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_disabled",
    )
    .await;
    sqlx::query("UPDATE resource_service_bindings SET snapshot_json = '{}'::jsonb WHERE id = $1")
        .bind(env.binding_id)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_not_linked",
    )
    .await;
    sqlx::query("UPDATE resource_service_bindings SET snapshot_json = '{\"status\":\"active\"}'::jsonb, tombstoned_at = NOW() WHERE id = $1").bind(env.binding_id).execute(&env.database).await.unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_not_linked",
    )
    .await;
}

#[tokio::test]
async fn exchange_disabled_user_cannot_obtain_a_ticket() {
    let env = setup().await;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(env.user_id)
        .execute(&env.database)
        .await
        .unwrap();
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_disabled",
    )
    .await;
}

#[tokio::test]
async fn exchange_unlink_stops_new_tickets_and_preserves_revocation_outbox() {
    let env = setup().await;
    let mut session = chenxing_auth::sessions::domain::Session::new(
        env.user_id.to_string(),
        std::time::Duration::from_secs(3600),
    )
    .unwrap();
    env.state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .unwrap();
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/auth/resource-services/bindings/{}",
                    env.binding_id
                ))
                .header("cookie", crate::oauth_flow::session_cookie(&session))
                .header("x-csrf-token", &session.csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_not_linked",
    )
    .await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM resource_service_revocation_outbox WHERE binding_id = $1",
    )
    .bind(env.binding_id)
    .fetch_one(&env.database)
    .await
    .unwrap();
    assert_eq!(count, 1);
    // Unlinking a provider is not OAuth revocation or a device reset.
    assert_eq!(
        userinfo(&env, "GET", &env.token).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn exchange_rate_limits_ticket_issuance_per_subject() {
    let env = setup().await;
    for _ in 0..10 {
        assert_eq!(
            exchange(&env, Some(&env.token), valid_body())
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    )
    .await;
}

#[tokio::test]
async fn exchange_login_ticket_is_neither_self_renewable_nor_an_oauth_access_token() {
    let env = setup().await;
    let body = http::json_body(exchange(&env, Some(&env.token), valid_body()).await).await;
    let ticket = body["login_ticket"].as_str().unwrap();
    assert_error(
        exchange(&env, Some(ticket), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
    for method in ["GET", "POST"] {
        let response = userinfo(&env, method, ticket).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(http::json_body(response).await["error"], "invalid_token");
        assert_eq!(
            userinfo(&env, method, &env.token).await.status(),
            StatusCode::OK
        );
    }
    // RFC 7009 returns 200 for unknown tokens; it must not consume a login ticket as AT.
    assert_eq!(revoke(&env, ticket).await.status(), StatusCode::OK);
    assert!(!env.state.revocations.is_revoked(ticket).await.unwrap());
    assert_eq!(revoke(&env, &env.token).await.status(), StatusCode::OK);
    assert!(env.state.revocations.is_revoked(&env.token).await.unwrap());
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
}

#[tokio::test]
async fn exchange_v1_is_retired_even_without_auth_or_valid_json() {
    let env = setup().await;
    for body in ["", "{", r#"{"device_id":"old-device"}"#] {
        let response = env
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/chenxing/exchange")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_error(response, StatusCode::GONE, "protocol_retired").await;
    }
}

#[tokio::test]
async fn exchange_revocation_store_outage_is_provider_unavailable() {
    let mut env = setup().await;
    let mut state = env.state.clone();
    // Cache-only store: a refused Redis connection cannot fall back to Postgres,
    // so the revocation check fail-closes instead of signing.
    state.revocations = TokenRevocationStore::new(closed_redis());
    env.router = api::router(state);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "provider_unavailable",
    )
    .await;
}

#[tokio::test]
async fn exchange_gateway_timeout_becomes_service_unavailable() {
    let app = Router::new()
        .route("/api/v2/auth/chenxing/exchange", post(gateway_timeout))
        .layer(from_fn(response_boundary));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/auth/chenxing/exchange")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_error(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
    )
    .await;
}

#[tokio::test]
async fn exchange_issuer_not_ready_is_service_unavailable() {
    let mut env = setup().await;
    let mut state = env.state.clone();
    // Invalid does not reload from the database, unlike AwaitingIssuer.
    state.issuer = IssuerRuntime::new_invalid(&state.config, 1);
    env.router = api::router(state);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
    )
    .await;
}

#[tokio::test]
async fn exchange_nonempty_allowlist_excluding_client_is_invalid_chenxing_token() {
    let mut env = setup().await;
    sqlx::query(
        "UPDATE resource_service_providers
            SET allowed_client_ids = ARRAY['other-client']::text[]
          WHERE id = $1",
    )
    .bind(env.provider_id)
    .execute(&env.database)
    .await
    .unwrap();
    // The grant gate drops a scope this client cannot see, which is the empty-list
    // 403. Keep cltermux:access on the platform allowlist so the provider is still
    // selected and the explicit allowed_client_ids check returns 401.
    let mut state = env.state.clone();
    state
        .config
        .client_registration_limits
        .allowed_scopes
        .push(SCOPE.to_owned());
    env.router = api::router(state);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
}

fn closed_redis() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("redis url")
}

async fn gateway_timeout() -> StatusCode {
    StatusCode::GATEWAY_TIMEOUT
}
