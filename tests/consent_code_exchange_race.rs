//! Issue #475: authorization-code exchange must not return tokens after a consent
//! revoke that commits between the grant gate and Refresh Token persist.
//!
//! The Client-row `FOR UPDATE` barrier parks `exchange_code` at
//! `clients.acquire_issuance_guard`, which is after `effective_grant_scopes`.
//! A real `revoke_consent` can then commit `state_version + 1` and clean existing
//! families before the parked exchange creates a new one. Releasing the barrier
//! lets persist finish; the post-persist fence must discard that family and
//! return `invalid_grant` without restoring the authorization code.

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
        revoke_consent_use_case::{RevokeConsentServices, revoke_consent},
        token_use_case::{self, OAuthError, TokenRequest},
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
    let (state, database, key_directory) =
        test_state_with_max_connections("consent_code_exchange_race", 32).await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "consent_code_exchange_race", &suffix).await;
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

async fn wait_until_exchange_reaches_client_guard<T>(
    transaction: &mut chenxing_auth::sqlx::Transaction<'_, chenxing_auth::sqlx::Postgres>,
    exchange: &tokio::task::JoinHandle<T>,
) -> bool {
    for _ in 0..2_000 {
        if exchange.is_finished() {
            return false;
        }
        let waiting: bool = chenxing_auth::sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                 FROM pg_locks waiting
                 JOIN pg_locks held
                   ON held.locktype = waiting.locktype
                  AND held.database IS NOT DISTINCT FROM waiting.database
                  AND held.relation IS NOT DISTINCT FROM waiting.relation
                  AND held.page IS NOT DISTINCT FROM waiting.page
                  AND held.tuple IS NOT DISTINCT FROM waiting.tuple
                  AND held.virtualxid IS NOT DISTINCT FROM waiting.virtualxid
                  AND held.transactionid IS NOT DISTINCT FROM waiting.transactionid
                  AND held.classid IS NOT DISTINCT FROM waiting.classid
                  AND held.objid IS NOT DISTINCT FROM waiting.objid
                  AND held.objsubid IS NOT DISTINCT FROM waiting.objsubid
                  AND held.pid = pg_backend_pid()
                  AND held.granted
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

async fn park_exchange_behind_client_guard(
    harness: &Harness,
    code: &AuthorizationCode,
) -> (
    chenxing_auth::sqlx::Transaction<'static, chenxing_auth::sqlx::Postgres>,
    tokio::task::JoinHandle<Result<token_use_case::TokenResponse, OAuthError>>,
) {
    let authenticated = authenticate(harness).await;
    let mut client_barrier = harness
        .database
        .begin()
        .await
        .expect("begin Client barrier");
    let _: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE client_id = $1 FOR UPDATE",
    )
    .bind(&harness.client_id)
    .fetch_one(&mut *client_barrier)
    .await
    .expect("lock Client row");

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
    if !wait_until_exchange_reaches_client_guard(&mut client_barrier, &exchange).await {
        if exchange.is_finished() {
            let early_result = exchange.await.expect("join early code exchange");
            panic!("exchange finished before the Client issuance guard: {early_result:?}");
        }
        panic!("exchange did not reach the Client issuance guard");
    }
    (client_barrier, exchange)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_committed_after_gate_but_before_persist_returns_no_tokens() {
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

    let (client_barrier, exchange) = park_exchange_behind_client_guard(&harness, &code).await;

    revoke_consent(
        RevokeConsentServices {
            consents: &harness.state.consents,
            refresh_tokens: &harness.state.refresh_tokens,
            revocations: &harness.state.revocations,
            audit: &harness.state.audit,
        },
        harness.user_id,
        &harness.client_id,
        None,
        None,
    )
    .await
    .expect("commit consent revoke while exchange is parked");
    client_barrier
        .rollback()
        .await
        .expect("release Client barrier after revoke commit");

    let result = exchange.await.expect("join code exchange");
    assert!(
        matches!(
            &result,
            Err(OAuthError::BadRequest {
                code: "invalid_grant",
                ..
            })
        ),
        "a revoke that commits first must reject the exchange, got {result:?}"
    );
    assert_eq!(
        refresh_count_for_grant(&harness).await,
        0,
        "the rejected exchange must discard the Refresh Token it persisted after revoke"
    );
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find authorization code after fence rejection")
            .is_none(),
        "fence rejection must not restore the already-consumed authorization code"
    );

    cleanup(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_succeeds_when_consent_stays_active_through_persist() {
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

    let (client_barrier, exchange) = park_exchange_behind_client_guard(&harness, &code).await;
    client_barrier
        .rollback()
        .await
        .expect("release Client barrier without revoke");

    let result = exchange.await.expect("join code exchange");
    let token = result.expect("exchange must succeed when consent stays active");
    assert!(!token.access_token.is_empty());
    assert!(token.id_token.is_some());
    assert_eq!(refresh_count_for_grant(&harness).await, 1);
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find consumed authorization code")
            .is_none()
    );

    if let Some(refresh) = token.refresh_token {
        let _ = harness.state.refresh_tokens.remove(&refresh).await;
    }
    cleanup(&harness).await;
}
