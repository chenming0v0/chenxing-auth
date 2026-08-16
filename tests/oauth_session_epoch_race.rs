//! Issue #476: token issuance must be linearizable with `users.session_epoch`.
//!
//! The barrier holds the same user advisory lock as `revoke_all_for_user`, then
//! advances epoch **without** revoking the Session row. Old #506 only locked
//! `user_sessions`, so that UPDATE did not conflict and tokens still issued.
//! If the implementation never takes the user lock, the wait helper panics.

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod support;

use std::{sync::Arc, time::Duration};

use chenxing_auth::{
    api,
    clients::{domain::ClientAuthMethod, service::AuthenticatedClient},
    oauth::{
        code::AuthorizationCode,
        refresh::RefreshToken,
        token_use_case::{self, OAuthError, RefreshExchangeError, TokenRequest},
    },
    sessions::domain::Session,
    settings::IssuerSnapshot,
    state::AppState,
};
use redis::AsyncCommands;
use tokio::sync::Barrier;
use uuid::Uuid;

use support::{
    create_test_client, ensure_owner_bootstrapped, register_test_user,
    test_state_with_max_connections,
};

const REDIRECT_URI: &str = "https://epoch.example/callback";
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
    let (state, database, key_directory) =
        test_state_with_max_connections("oauth_session_epoch_race", 16).await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_session_epoch_race", &suffix).await;
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

async fn authenticate(harness: &Harness) -> AuthenticatedClient {
    harness
        .state
        .clients
        .authenticate_credentials(
            &harness.client_id,
            ClientAuthMethod::Basic,
            Some(&harness.client_secret),
        )
        .await
        .expect("authenticate client")
        .expect("valid client credentials")
}

fn issuer(state: &AppState) -> IssuerSnapshot {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
        .as_ref()
        .clone()
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
    .bind(time::OffsetDateTime::now_utc())
    .execute(&harness.database)
    .await
    .expect("save consent");
}

async fn saved_session(harness: &Harness) -> Session {
    let ttl = Duration::from_secs(3600);
    let mut session = Session::new(harness.user_id.to_string(), ttl).expect("session");
    harness
        .state
        .sessions
        .save(&mut session, ttl)
        .await
        .expect("persist session");
    session
}

async fn current_session_epoch(harness: &Harness) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(harness.user_id)
        .fetch_one(&harness.database)
        .await
        .expect("read session_epoch")
}

fn authorization_code(harness: &Harness, session_token: String) -> AuthorizationCode {
    AuthorizationCode::new_with_nonce(
        harness.client_id.clone(),
        REDIRECT_URI.to_owned(),
        harness.user_id.to_string(),
        vec!["openid".to_owned()],
        CHALLENGE.to_owned(),
        None,
        Some(session_token),
    )
    .with_issuer_generation(issuer(&harness.state).generation())
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

async fn persist_refresh(harness: &Harness, authenticated: &AuthenticatedClient) -> RefreshToken {
    let token = RefreshToken::new_at_with_client_secret_version(
        harness.client_id.clone(),
        harness.user_id.to_string(),
        vec!["openid".to_owned()],
        authenticated.client_secret_version(),
        current_session_epoch(harness).await,
        issuer(&harness.state).generation(),
        harness.state.clock.now(),
    );
    harness
        .state
        .refresh_tokens
        .save(&token)
        .await
        .expect("persist refresh token");
    token
}

async fn begin_epoch_barrier(
    harness: &Harness,
) -> chenxing_auth::sqlx::Transaction<'_, chenxing_auth::sqlx::Postgres> {
    let mut barrier = harness.database.begin().await.expect("begin epoch barrier");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)")
        .bind(harness.user_id)
        .execute(&mut *barrier)
        .await
        .expect("take user advisory lock");
    let _: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT session_epoch FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(harness.user_id)
    .fetch_one(&mut *barrier)
    .await
    .expect("lock users row");
    barrier
}

async fn wait_until_exchange_takes_user_lock<T>(
    transaction: &mut chenxing_auth::sqlx::Transaction<'_, chenxing_auth::sqlx::Postgres>,
    exchange: &tokio::task::JoinHandle<T>,
) -> bool {
    for _ in 0..500 {
        if exchange.is_finished() {
            return false;
        }
        let waiting: bool = chenxing_auth::sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                 FROM pg_locks waiting
                 WHERE NOT waiting.granted
                   AND waiting.pid <> pg_backend_pid()
             )",
        )
        .fetch_one(&mut **transaction)
        .await
        .expect("inspect blocked exchange");
        if waiting {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

async fn advance_epoch_without_revoking_session(
    mut barrier: chenxing_auth::sqlx::Transaction<'_, chenxing_auth::sqlx::Postgres>,
    user_id: i64,
) {
    chenxing_auth::sqlx::query(
        "UPDATE users SET session_epoch = session_epoch + 1, updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *barrier)
    .await
    .expect("advance session_epoch without revoking sessions");
    barrier.commit().await.expect("commit epoch barrier");
}

async fn refresh_count_for_grant(harness: &Harness) -> i64 {
    let mut redis = harness
        .state
        .redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let grant_index = harness.state.config.redis_keyspace.prefix(&format!(
        "cx:refresh:grant_idx:{}:{}",
        harness.user_id, harness.client_id
    ));
    redis
        .scard(grant_index)
        .await
        .expect("refresh grant index size")
}

async fn session_row_still_live(harness: &Harness, session: &Session) -> bool {
    chenxing_auth::sqlx::query_scalar("SELECT revoked_at IS NULL FROM user_sessions WHERE id = $1")
        .bind(session.id)
        .fetch_one(&harness.database)
        .await
        .expect("session row liveness")
}

fn assert_invalid_grant_code(result: &Result<token_use_case::TokenResponse, OAuthError>) {
    assert!(
        matches!(
            result,
            Err(OAuthError::BadRequest {
                code: "invalid_grant",
                ..
            })
        ),
        "expected invalid_grant, got {result:?}"
    );
}

fn assert_invalid_grant_refresh(
    result: &Result<token_use_case::TokenResponse, RefreshExchangeError>,
) {
    assert!(
        matches!(
            result,
            Err(RefreshExchangeError::OAuth(OAuthError::BadRequest {
                code: "invalid_grant",
                ..
            }))
        ),
        "expected invalid_grant, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn epoch_advance_without_session_revoke_rejects_authorization_code() {
    let harness = setup().await;
    save_consent(&harness).await;
    let session = saved_session(&harness).await;
    let code = authorization_code(&harness, session.token.clone());
    harness
        .state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let authenticated = authenticate(&harness).await;

    let mut barrier = begin_epoch_barrier(&harness).await;
    let start = Arc::new(Barrier::new(2));
    let exchange = {
        let state = harness.state.clone();
        let client_id = harness.client_id.clone();
        let issuer = issuer(&state);
        let code_value = code.value.clone();
        let start = start.clone();
        tokio::spawn(async move {
            start.wait().await;
            token_use_case::exchange_code(
                &state,
                code_request(&client_id, &code_value),
                authenticated,
                &issuer,
            )
            .await
        })
    };
    start.wait().await;
    if !wait_until_exchange_takes_user_lock(&mut barrier, &exchange).await {
        if exchange.is_finished() {
            let early = exchange.await.expect("join early code exchange");
            panic!("exchange finished before the user-generation fence: {early:?}");
        }
        panic!(
            "exchange did not take the user lock within 5s — implementation never fenced session_epoch"
        );
    }

    advance_epoch_without_revoking_session(barrier, harness.user_id).await;
    assert!(
        session_row_still_live(&harness, &session).await,
        "this race must advance epoch without revoking the Session row"
    );

    let result = exchange.await.expect("join code exchange");
    assert_invalid_grant_code(&result);
    assert_eq!(
        refresh_count_for_grant(&harness).await,
        0,
        "rejected exchange must leave no successor Refresh Token"
    );
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find compensated authorization code")
            .is_some(),
        "epoch rejection must restore the authorization code"
    );

    let _ = harness.state.authorization_codes.take(&code.value).await;
    cleanup(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn epoch_advance_without_session_revoke_rejects_refresh_and_rolls_back() {
    let harness = setup().await;
    save_consent(&harness).await;
    let _session = saved_session(&harness).await;
    let authenticated = authenticate(&harness).await;
    let previous = persist_refresh(&harness, &authenticated).await;
    assert_eq!(refresh_count_for_grant(&harness).await, 1);

    let mut barrier = begin_epoch_barrier(&harness).await;
    let start = Arc::new(Barrier::new(2));
    let exchange = {
        let state = harness.state.clone();
        let client_id = harness.client_id.clone();
        let issuer = issuer(&state);
        let refresh_value = previous.value.clone();
        let start = start.clone();
        tokio::spawn(async move {
            start.wait().await;
            token_use_case::exchange_refresh_token(
                &state,
                &issuer,
                refresh_request(&client_id, &refresh_value),
                authenticated,
            )
            .await
        })
    };
    start.wait().await;
    if !wait_until_exchange_takes_user_lock(&mut barrier, &exchange).await {
        if exchange.is_finished() {
            let early = exchange.await.expect("join early refresh exchange");
            panic!("refresh finished before the user-generation fence: {early:?}");
        }
        panic!(
            "refresh did not take the user lock within 5s — implementation never fenced session_epoch"
        );
    }

    advance_epoch_without_revoking_session(barrier, harness.user_id).await;

    let result = exchange.await.expect("join refresh exchange");
    assert_invalid_grant_refresh(&result);

    let restored = harness
        .state
        .refresh_tokens
        .find(&previous.value)
        .await
        .expect("find previous refresh token");
    assert!(
        restored.is_some(),
        "rollback_rotation must restore the previous Refresh Token when the successor is still current"
    );
    assert_eq!(
        refresh_count_for_grant(&harness).await,
        1,
        "successor must disappear; previous remains the sole grant member"
    );

    let _ = harness.state.refresh_tokens.remove(&previous.value).await;
    cleanup(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unchanged_epoch_still_issues_authorization_code_and_refresh_tokens() {
    let harness = setup().await;
    save_consent(&harness).await;
    let session = saved_session(&harness).await;
    let code = authorization_code(&harness, session.token.clone());
    harness
        .state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let authenticated = authenticate(&harness).await;
    let epoch_before = current_session_epoch(&harness).await;

    let issued = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &code.value),
        authenticate(&harness).await,
        &issuer(&harness.state),
    )
    .await
    .expect("unchanged epoch must issue tokens");
    let refresh_value = issued
        .refresh_token
        .expect("authorization-code exchange issues a refresh token");
    assert_eq!(refresh_count_for_grant(&harness).await, 1);
    assert_eq!(current_session_epoch(&harness).await, epoch_before);

    let refreshed = token_use_case::exchange_refresh_token(
        &harness.state,
        &issuer(&harness.state),
        refresh_request(&harness.client_id, &refresh_value),
        authenticated,
    )
    .await
    .expect("unchanged epoch must rotate the refresh token");
    let successor = refreshed
        .refresh_token
        .expect("refresh exchange issues a successor");
    assert_ne!(successor, refresh_value);
    assert!(
        harness
            .state
            .refresh_tokens
            .find(&refresh_value)
            .await
            .expect("find consumed refresh token")
            .is_none(),
        "successful rotation consumes the previous Refresh Token"
    );
    assert!(
        harness
            .state
            .refresh_tokens
            .find(&successor)
            .await
            .expect("find successor refresh token")
            .is_some(),
        "successful rotation must persist the successor"
    );
    assert_eq!(refresh_count_for_grant(&harness).await, 1);

    let _ = harness.state.refresh_tokens.remove(&successor).await;
    cleanup(&harness).await;
}
