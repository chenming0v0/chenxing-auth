//! Issue #310: an authentication result from an old Client Secret generation
//! must not mint a live Refresh Token after secret rotation commits.
//!
//! These tests deliberately split authentication from token persistence. That
//! makes the TOCTOU window deterministic instead of hoping a scheduler lands in
//! it, then a final mixed concurrency test checks the same invariant without
//! assuming whether issuance or rotation wins.

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod support;

use std::sync::Arc;

use chenxing_auth::{
    api,
    clients::{domain::ClientAuthMethod, service::AuthenticatedClient},
    oauth::{
        code::AuthorizationCode,
        refresh::RefreshToken,
        token_use_case::{self, OAuthError, RefreshExchangeError, TokenRequest, TokenResponse},
    },
    settings::{IssuerSnapshot, issuer::IssuerRecord},
    state::AppState,
};
use time::OffsetDateTime;
use tokio::sync::Barrier;
use uuid::Uuid;

use support::{create_test_client, ensure_owner_bootstrapped, register_test_user, test_state};

const REDIRECT_URI: &str = "https://disabled.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Harness {
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    user_id: i64,
    client_id: String,
    client_secret: String,
}

async fn setup() -> Harness {
    let (state, database, key_directory) = test_state("client_secret_token_race").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "client_secret_token_race", &suffix).await;
    let (user_id, _, _, _) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    Harness {
        state,
        database,
        key_directory,
        user_id,
        client_id,
        client_secret,
    }
}

async fn cleanup(harness: &Harness) {
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(&harness.client_id)
        .execute(&harness.database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(harness.user_id)
        .execute(&harness.database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(&harness.key_directory);
}

async fn authenticate(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
) -> AuthenticatedClient {
    state
        .clients
        .authenticate_credentials(client_id, ClientAuthMethod::Basic, Some(client_secret))
        .await
        .expect("authenticate client")
        .expect("valid client credentials")
}

fn test_issuer(state: &AppState) -> Arc<IssuerSnapshot> {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
}

/// #508：无会话绑定的授权码在 Token 端点 fail-closed，走兑换路径的测试
/// 必须先把码绑定到一条已持久化的浏览器会话上。
async fn browser_session_token(harness: &Harness) -> String {
    let mut session = chenxing_auth::sessions::domain::Session::new(
        harness.user_id.to_string(),
        std::time::Duration::from_secs(3600),
    )
    .expect("session");
    harness
        .state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session.token
}

fn authorization_code(
    client_id: &str,
    user_id: i64,
    session_token: &str,
    issuer_generation: i64,
) -> AuthorizationCode {
    AuthorizationCode::new_with_nonce(
        client_id.to_owned(),
        REDIRECT_URI.to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned()],
        CHALLENGE.to_owned(),
        None,
        Some(session_token.to_owned()),
    )
    .with_issuer_generation(issuer_generation)
}

fn code_request(client_id: &str, code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_owned(),
        code: Some(code.to_owned()),
        redirect_uri: Some(REDIRECT_URI.to_owned()),
        client_id: Some(client_id.to_owned()),
        client_secret: None,
        code_verifier: Some(VERIFIER.to_owned()),
        refresh_token: None,
        scope: None,
    }
}

fn refresh_request(client_id: &str, refresh_token: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "refresh_token".to_owned(),
        code: None,
        redirect_uri: None,
        client_id: Some(client_id.to_owned()),
        client_secret: None,
        code_verifier: None,
        refresh_token: Some(refresh_token.to_owned()),
        scope: None,
    }
}

async fn save_consent(harness: &Harness) {
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE
         SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(harness.user_id)
    .bind(&harness.client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(OffsetDateTime::now_utc())
    .execute(&harness.database)
    .await
    .expect("save consent");
}

/// 当前用户的 `session_epoch`（Issue #409）：直接构造的 Refresh Token 必须
/// stamp 这个值，否则兑换路径的凭据代际比对会先于本测试要验证的
/// client_secret_version 判定拒绝 token。
async fn current_session_epoch(harness: &Harness) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(harness.user_id)
        .fetch_one(&harness.database)
        .await
        .expect("read user session epoch")
}

fn issued_refresh(response: TokenResponse) -> String {
    response
        .refresh_token
        .expect("successful exchange issues a refresh token")
}

#[tokio::test]
async fn authorization_code_cannot_persist_after_authenticated_secret_version_changes() {
    let harness = setup().await;
    let authenticated =
        authenticate(&harness.state, &harness.client_id, &harness.client_secret).await;
    let session_token = browser_session_token(&harness).await;
    let code = authorization_code(
        &harness.client_id,
        harness.user_id,
        &session_token,
        test_issuer(&harness.state).generation(),
    );
    harness
        .state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    save_consent(&harness).await;

    harness
        .state
        .clients
        .rotate_secret(&harness.client_id)
        .await
        .expect("rotate client secret");

    let result = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &code.value),
        authenticated,
        &test_issuer(&harness.state),
    )
    .await;
    assert_eq!(
        result.expect_err("stale authentication must not exchange the code"),
        OAuthError::InvalidClient
    );
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find rejected authorization code")
            .is_some(),
        "version rejection must happen before consuming the authorization code"
    );
    let _ = harness.state.authorization_codes.take(&code.value).await;
    cleanup(&harness).await;
}

/// Issue #492: a Refresh Token is a credential of the Issuer generation that
/// created it. After a hot switch, the old grant must not be upgraded into a
/// token response whose `iss` belongs to the new Issuer.
#[tokio::test]
async fn refresh_token_cannot_cross_an_issuer_generation_change() {
    let harness = setup().await;
    let authenticated =
        authenticate(&harness.state, &harness.client_id, &harness.client_secret).await;
    let session_token = browser_session_token(&harness).await;
    let code = authorization_code(
        &harness.client_id,
        harness.user_id,
        &session_token,
        test_issuer(&harness.state).generation(),
    );
    harness
        .state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    save_consent(&harness).await;

    let issuer_a = test_issuer(&harness.state);
    let response = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &code.value),
        authenticated.clone(),
        &issuer_a,
    )
    .await
    .expect("exchange authorization code under issuer A");
    let refresh_value = issued_refresh(response);
    let stored = harness
        .state
        .refresh_tokens
        .find(&refresh_value)
        .await
        .expect("load issuer-bound refresh token")
        .expect("refresh token was persisted");
    assert_eq!(stored.issuer_generation, Some(issuer_a.generation()));

    harness
        .state
        .issuer
        .apply(&IssuerRecord {
            // COOKIE_SECURE=false 只放行 loopback HTTP issuer（issuer_runtime 的
            // apply 校验），Issuer B 必须保持同族形式；#492 验证的是代际边界，
            // 不依赖具体 URL。
            value: "http://127.0.0.1:3999".to_owned(),
            generation: issuer_a.generation() + 1,
            updated_at: harness.state.clock.now(),
        })
        .expect("apply issuer B");
    let issuer_b = test_issuer(&harness.state);
    assert_ne!(issuer_b.generation(), issuer_a.generation());

    let mut legacy_refresh = RefreshToken::new_at_with_client_secret_version(
        harness.client_id.clone(),
        harness.user_id.to_string(),
        vec!["openid".to_owned()],
        authenticated.client_secret_version(),
        current_session_epoch(&harness).await,
        issuer_b.generation(),
        harness.state.clock.now(),
    );
    legacy_refresh.issuer_generation = None;
    harness
        .state
        .refresh_tokens
        .save(&legacy_refresh)
        .await
        .expect("save legacy refresh token without issuer generation");

    let result = token_use_case::exchange_refresh_token(
        &harness.state,
        &issuer_b,
        refresh_request(&harness.client_id, &refresh_value),
        authenticated.clone(),
    )
    .await;
    assert!(matches!(
        result,
        Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
            code: "invalid_grant",
            ..
        }))
    ));
    let preserved = harness
        .state
        .refresh_tokens
        .find(&refresh_value)
        .await
        .expect("reload rejected refresh token")
        .expect("generation rejection must happen before token rotation");
    assert_eq!(preserved.issuer_generation, Some(issuer_a.generation()));

    let legacy_result = token_use_case::exchange_refresh_token(
        &harness.state,
        &issuer_b,
        refresh_request(&harness.client_id, &legacy_refresh.value),
        authenticated,
    )
    .await;
    assert!(matches!(
        legacy_result,
        Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
            code: "invalid_grant",
            ..
        }))
    ));
    assert!(
        harness
            .state
            .refresh_tokens
            .find(&legacy_refresh.value)
            .await
            .expect("reload rejected legacy refresh token")
            .is_some(),
        "legacy generation rejection must happen before token rotation"
    );

    harness
        .state
        .refresh_tokens
        .remove(&refresh_value)
        .await
        .expect("cleanup refresh token");
    harness
        .state
        .refresh_tokens
        .remove(&legacy_refresh.value)
        .await
        .expect("cleanup legacy refresh token");
    cleanup(&harness).await;
}

#[tokio::test]
async fn refresh_written_after_rotation_is_inert_even_if_revocation_already_ran() {
    let harness = setup().await;
    save_consent(&harness).await;
    // Existing Clients enter the rollout with unversioned Refresh Tokens still
    // admitted. The first post-upgrade rotation must close that window.
    chenxing_auth::sqlx::query(
        "UPDATE oauth_clients SET allow_legacy_refresh_tokens = TRUE WHERE client_id = $1",
    )
    .bind(&harness.client_id)
    .execute(&harness.database)
    .await
    .expect("open legacy compatibility window");
    let stale_authentication =
        authenticate(&harness.state, &harness.client_id, &harness.client_secret).await;
    assert!(stale_authentication.allows_legacy_refresh_tokens());
    let stale_refresh = RefreshToken::new_at_with_client_secret_version(
        harness.client_id.clone(),
        harness.user_id.to_string(),
        vec!["openid".to_owned()],
        stale_authentication.client_secret_version(),
        current_session_epoch(&harness).await,
        test_issuer(&harness.state).generation(),
        harness.state.clock.now(),
    );
    let mut stale_legacy_refresh = RefreshToken::new_at_with_client_secret_version(
        harness.client_id.clone(),
        harness.user_id.to_string(),
        vec!["openid".to_owned()],
        0,
        current_session_epoch(&harness).await,
        test_issuer(&harness.state).generation(),
        harness.state.clock.now(),
    );
    stale_legacy_refresh.client_secret_version = None;

    let rotated = harness
        .state
        .clients
        .rotate_secret(&harness.client_id)
        .await
        .expect("rotate client secret");
    // Recreate the exact bad ordering from #310: the rotation scan has already
    // completed, then an in-flight request attempts to publish an old-version
    // token. Production uses the issuance fence; this direct store write also
    // verifies the payload-version backstop if Redis revocation ever fails.
    harness
        .state
        .refresh_tokens
        .save(&stale_refresh)
        .await
        .expect("simulate stale in-flight persistence");
    harness
        .state
        .refresh_tokens
        .save(&stale_legacy_refresh)
        .await
        .expect("simulate legacy in-flight persistence");

    let stale_result = token_use_case::exchange_refresh_token(
        &harness.state,
        &test_issuer(&harness.state),
        refresh_request(&harness.client_id, &stale_refresh.value),
        stale_authentication,
    )
    .await;
    assert!(matches!(
        stale_result,
        Err(RefreshExchangeError::OAuth(OAuthError::InvalidClient))
    ));

    let current_authentication =
        authenticate(&harness.state, &harness.client_id, &rotated.client_secret).await;
    assert!(!current_authentication.allows_legacy_refresh_tokens());
    let current_result = token_use_case::exchange_refresh_token(
        &harness.state,
        &test_issuer(&harness.state),
        refresh_request(&harness.client_id, &stale_refresh.value),
        current_authentication.clone(),
    )
    .await;
    assert!(matches!(
        current_result,
        Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
            code: "invalid_grant",
            ..
        }))
    ));
    let legacy_result = token_use_case::exchange_refresh_token(
        &harness.state,
        &test_issuer(&harness.state),
        refresh_request(&harness.client_id, &stale_legacy_refresh.value),
        current_authentication,
    )
    .await;
    assert!(matches!(
        legacy_result,
        Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
            code: "invalid_grant",
            ..
        }))
    ));
    assert!(
        harness
            .state
            .refresh_tokens
            .find(&stale_refresh.value)
            .await
            .expect("find inert stale token")
            .is_some(),
        "the version check, not accidental deletion, must make the stale token unusable"
    );
    assert!(
        harness
            .state
            .refresh_tokens
            .find(&stale_legacy_refresh.value)
            .await
            .expect("find inert legacy token")
            .is_some(),
        "closing the legacy window must reject even a physically present token"
    );

    harness
        .state
        .refresh_tokens
        .remove(&stale_refresh.value)
        .await
        .expect("cleanup stale refresh token");
    harness
        .state
        .refresh_tokens
        .remove(&stale_legacy_refresh.value)
        .await
        .expect("cleanup stale legacy refresh token");
    cleanup(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_rotation_leaves_no_live_refresh_from_either_issuance_path() {
    let harness = setup().await;
    save_consent(&harness).await;
    let authenticated =
        authenticate(&harness.state, &harness.client_id, &harness.client_secret).await;
    let per_path = 3_usize;
    let barrier = Arc::new(Barrier::new(per_path * 2 + 1));

    let mut codes = Vec::with_capacity(per_path);
    let mut code_tasks = Vec::with_capacity(per_path);
    for _ in 0..per_path {
        let session_token = browser_session_token(&harness).await;
        let code = authorization_code(
            &harness.client_id,
            harness.user_id,
            &session_token,
            test_issuer(&harness.state).generation(),
        );
        harness
            .state
            .authorization_codes
            .save(&code)
            .await
            .expect("save concurrent authorization code");
        codes.push(code.value.clone());
        let state = harness.state.clone();
        let client_id = harness.client_id.clone();
        let authenticated = authenticated.clone();
        let issuer = test_issuer(&state);
        let barrier = barrier.clone();
        code_tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match token_use_case::exchange_code(
                &state,
                code_request(&client_id, &code.value),
                authenticated,
                &issuer,
            )
            .await
            {
                Ok(response) => Some(issued_refresh(response)),
                Err(OAuthError::InvalidClient) => None,
                Err(error) => panic!("unexpected authorization-code outcome: {error}"),
            }
        }));
    }

    let mut original_refreshes = Vec::with_capacity(per_path);
    let mut refresh_tasks = Vec::with_capacity(per_path);
    for _ in 0..per_path {
        let refresh = RefreshToken::new_at_with_client_secret_version(
            harness.client_id.clone(),
            harness.user_id.to_string(),
            vec!["openid".to_owned()],
            authenticated.client_secret_version(),
            current_session_epoch(&harness).await,
            test_issuer(&harness.state).generation(),
            harness.state.clock.now(),
        );
        harness
            .state
            .refresh_tokens
            .save(&refresh)
            .await
            .expect("save concurrent refresh token");
        original_refreshes.push(refresh.value.clone());
        let state = harness.state.clone();
        let client_id = harness.client_id.clone();
        let authenticated = authenticated.clone();
        let issuer = test_issuer(&state);
        let barrier = barrier.clone();
        refresh_tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match token_use_case::exchange_refresh_token(
                &state,
                &issuer,
                refresh_request(&client_id, &refresh.value),
                authenticated,
            )
            .await
            {
                Ok(response) => Some(issued_refresh(response)),
                Err(RefreshExchangeError::OAuth(OAuthError::InvalidClient))
                | Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
                    code: "invalid_grant",
                    ..
                })) => None,
                Err(error) => panic!("unexpected refresh outcome: {error}"),
            }
        }));
    }

    let rotation = {
        let clients = harness.state.clients.clone();
        let client_id = harness.client_id.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            clients.rotate_secret(&client_id).await
        })
    };
    rotation
        .await
        .expect("join secret rotation")
        .expect("commit secret rotation");

    let mut issued = Vec::new();
    for task in code_tasks {
        if let Some(value) = task.await.expect("join authorization-code exchange") {
            issued.push(value);
        }
    }
    for task in refresh_tasks {
        if let Some(value) = task.await.expect("join refresh exchange") {
            issued.push(value);
        }
    }

    for value in issued {
        assert!(
            harness
                .state
                .refresh_tokens
                .find(&value)
                .await
                .expect("find concurrently issued refresh token")
                .is_none(),
            "a successful pre-commit issuance must be removed by the committing rotation"
        );
    }
    for value in original_refreshes {
        assert!(
            harness
                .state
                .refresh_tokens
                .find(&value)
                .await
                .expect("find original refresh token")
                .is_none(),
            "rotation must remove every original refresh token"
        );
    }
    for value in codes {
        let _ = harness.state.authorization_codes.take(&value).await;
    }
    cleanup(&harness).await;
}
