//! Issue #516: authorization codes are bound to the Issuer generation that minted them.
//!
//! A code issued under Issuer A must not redeem after a hot switch to Issuer B.
//! Rejection happens before CAS, so the unused code is not burned. A newly
//! issued B-era code still redeems. Legacy payloads without generation fail closed.

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod support;

use super::support::{
    create_test_client, ensure_owner_bootstrapped, register_test_user, test_state,
};
use chenxing_auth::oauth::handlers::issue_authorization_code_result;
use chenxing_auth::oauth::token_use_case::OAuthError;
use chenxing_auth::oauth::{
    authorization::ValidatedAuthorizationRequest,
    code::AuthorizationCode,
    handlers::AuthorizationCodeIssue,
    token_use_case::{self, TokenRequest},
};
use chenxing_auth::settings::{IssuerSnapshot, issuer::IssuerRecord};
use chenxing_auth::sessions::domain::session_token_hash;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use chenxing_auth::{
    api,
    clients::{domain::ClientAuthMethod, service::AuthenticatedClient},
    oauth::{
        authorization::ValidatedAuthorizationRequest,
        handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
        token_use_case::{self, OAuthError, TokenRequest},
    },
    sessions::domain::session_token_hash,
    settings::{IssuerSnapshot, issuer::IssuerRecord},
    state::AppState,
};
use time::OffsetDateTime;
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
    let (state, database, key_directory) = test_state("authorization_code_issuer").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "authorization_code_issuer", &suffix).await;
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

fn test_issuer(state: &AppState) -> Arc<IssuerSnapshot> {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
}

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

fn validated_request(harness: &Harness, session_token: &str) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: harness.client_id.clone(),
        redirect_uri: REDIRECT_URI.to_owned(),
        scopes: vec!["openid".to_owned()],
        state: "issuer-516-state".to_owned(),
        nonce: None,
        code_challenge: CHALLENGE.to_owned(),
        owner_user_id: None,
        session_token_hash: Some(session_token_hash(session_token)),
    }
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

fn code_from_redirect(redirect: &str) -> String {
    url::Url::parse(redirect)
        .expect("issued redirect is a URL")
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization redirect includes a code")
}

async fn issue_code(harness: &Harness, issuer: &IssuerSnapshot, session_token: &str) -> String {
    let issued = issue_authorization_code_result(
        &harness.state,
        issuer,
        harness.user_id.to_string(),
        validated_request(harness, session_token),
        None,
        None,
    )
    .await
    .expect("issue authorization code");
    let AuthorizationCodeIssue::Redirect(redirect) = issued else {
        panic!("authorization must not be quota-limited in this fixture");
    };
    code_from_redirect(&redirect)
}

fn switch_to_issuer_b(harness: &Harness, issuer_a: &IssuerSnapshot) -> Arc<IssuerSnapshot> {
    harness
        .state
        .issuer
        .apply(&IssuerRecord {
            // COOKIE_SECURE=false 只放行 loopback HTTP issuer。
            value: "http://127.0.0.1:3999".to_owned(),
            generation: issuer_a.generation() + 1,
            updated_at: harness.state.clock.now(),
        })
        .expect("apply issuer B");
    let issuer_b = test_issuer(&harness.state);
    assert_ne!(issuer_b.generation(), issuer_a.generation());
    issuer_b
}

/// Issue #516: A-era unused codes cannot be upgraded into B-era tokens. A new
/// B-era code still redeems. Missing generation fails closed before CAS.
#[tokio::test]
async fn authorization_code_cannot_cross_an_issuer_generation_change() {
    let harness = setup().await;
    save_consent(&harness).await;
    let session_token = browser_session_token(&harness).await;
    let issuer_a = test_issuer(&harness.state);
    let code_a = issue_code(&harness, issuer_a.as_ref(), &session_token).await;

    let stored_a = harness
        .state
        .authorization_codes
        .find(&code_a)
        .await
        .expect("load A-era authorization code")
        .expect("A-era code was persisted");
    assert_eq!(stored_a.issuer_generation, Some(issuer_a.generation()));

    let issuer_b = switch_to_issuer_b(&harness, issuer_a.as_ref());
    let authenticated = authenticate(&harness).await;

    let crossed = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &code_a),
        authenticated.clone(),
        issuer_b.as_ref(),
    )
    .await;
    assert_eq!(
        crossed.expect_err("A-era code must not redeem under issuer B"),
        OAuthError::BadRequest {
            code: "invalid_grant",
            description: "authorization code is invalid",
        }
    );
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code_a)
            .await
            .expect("reload rejected A-era code")
            .is_some(),
        "generation rejection must happen before authorization-code CAS"
    );

    let mut legacy = stored_a.clone();
    legacy.value = format!("cx-code-{}", Uuid::new_v4().simple());
    legacy.issuer_generation = None;
    harness
        .state
        .authorization_codes
        .save(&legacy)
        .await
        .expect("save legacy authorization code without issuer generation");
    let legacy_result = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &legacy.value),
        authenticated.clone(),
        issuer_b.as_ref(),
    )
    .await;
    assert_eq!(
        legacy_result.expect_err("legacy code must fail closed"),
        OAuthError::BadRequest {
            code: "invalid_grant",
            description: "authorization code is invalid",
        }
    );
    assert!(
        harness
            .state
            .authorization_codes
            .find(&legacy.value)
            .await
            .expect("reload rejected legacy code")
            .is_some(),
        "legacy generation rejection must happen before authorization-code CAS"
    );

    let code_b = issue_code(&harness, issuer_b.as_ref(), &session_token).await;
    let stored_b = harness
        .state
        .authorization_codes
        .find(&code_b)
        .await
        .expect("load B-era authorization code")
        .expect("B-era code was persisted");
    assert_eq!(stored_b.issuer_generation, Some(issuer_b.generation()));

    let redeemed = token_use_case::exchange_code(
        &harness.state,
        code_request(&harness.client_id, &code_b),
        authenticated,
        issuer_b.as_ref(),
    )
    .await
    .expect("B-era code must redeem under the current issuer");
    assert!(redeemed.refresh_token.is_some());
    assert!(
        harness
            .state
            .authorization_codes
            .find(&code_b)
            .await
            .expect("reload redeemed B-era code")
            .is_none(),
        "successful B-era exchange still consumes the authorization code once"
    );

    let _ = harness.state.authorization_codes.take(&code_a).await;
    let _ = harness.state.authorization_codes.take(&legacy.value).await;
    if let Some(refresh) = redeemed.refresh_token.as_deref() {
        let _ = harness.state.refresh_tokens.remove(refresh).await;
    }
    cleanup(&harness).await;
}
