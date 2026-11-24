use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use chenxing_auth::{api, oauth::token::issue_access_token, sqlx, state::AppState};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "provider.rs"]
mod provider;
pub(super) use provider::ExchangeProvider;

pub(super) const CLIENT: &str = "v2-exchange-test-client";
pub(super) const SCOPE: &str = "cltermux:access";

pub(super) struct Env {
    pub router: Router,
    pub state: AppState,
    pub database: sqlx::PgPool,
    pub user_id: i64,
    pub provider_id: Uuid,
    pub binding_id: Uuid,
    pub token: String,
    pub stub: Arc<ExchangeProvider>,
}

pub(super) async fn setup() -> Env {
    let (mut state, database, _, _, suffix) =
        crate::harness::HarnessBuilder::new("resource_service_exchange")
            .redis_keyspace(
                chenxing_auth::redis_keyspace::RedisKeyspace::new(&format!(
                    "exchange-{}",
                    Uuid::new_v4().simple()
                ))
                .unwrap(),
            )
            .qps_window_override()
            .build_state()
            .await;
    let user_id: i64 = sqlx::query_scalar("INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at) VALUES ($1, $2, $2, 'not-used', NOW(), NOW()) RETURNING id")
        .bind(format!("v2-{suffix}")).bind(format!("v2-{suffix}@example.test")).fetch_one(&database).await.unwrap();
    sqlx::query("INSERT INTO oauth_clients (client_id, client_name, redirect_uris, scopes, auth_method, created_at) VALUES ($1, 'Exchange Test', '[\"https://example.test/callback\"]'::jsonb, '[]'::jsonb, 'none', NOW())")
        .bind(CLIENT).execute(&database).await.unwrap();
    let provider_id = seed_provider(&database, "cltermux", SCOPE).await;
    let stub = Arc::new(ExchangeProvider::new(database.clone()));
    state.resource_services = state
        .resource_services
        .clone()
        .with_transport_override(stub.clone());
    let binding_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resource_service_bindings (id, provider_id, user_id, uid, issuer, generation, snapshot_json, created_at, updated_at) VALUES ($1, $2, $3, 'cltermux:42', 'https://cltermux.example.test', 1, '{\"status\":\"active\",\"fields\":[]}'::jsonb, NOW(), NOW())")
        .bind(binding_id).bind(provider_id).bind(user_id).execute(&database).await.unwrap();
    seed_query_credentials(&state, &database, provider_id, binding_id).await;
    let mut env = Env {
        router: api::router(state.clone()),
        state,
        database,
        user_id,
        provider_id,
        binding_id,
        token: String::new(),
        stub,
    };
    set_package(&env, Some("top.clyact")).await;
    grant_scopes(&env, &["openid", SCOPE]).await;
    env.token = token_for(&env, &["openid", SCOPE]);
    env
}

async fn seed_query_credentials(
    state: &AppState,
    database: &sqlx::PgPool,
    provider_id: Uuid,
    binding_id: Uuid,
) {
    use chenxing_auth::resource_services::{
        SecretContext, SecretString, encrypt_secret, load_account_provider_secret_manager,
    };
    let secrets = load_account_provider_secret_manager(&state.config.key_directory, false)
        .await
        .unwrap();
    let secret = encrypt_secret(
        &secrets,
        SecretContext::ResourceServiceProvider(provider_id),
        &SecretString::new("0123456789abcdef0123456789abcdef".to_owned()),
    )
    .unwrap()
    .encode();
    let mut bundle: Value = serde_json::from_str(include_str!(
        "../../../docs/account-provider-v1/fixtures/refresh-response.json"
    ))
    .unwrap();
    bundle["issuer"] = json!("https://cltermux.example.test");
    bundle["client_binding_id"] = json!(binding_id.to_string());
    bundle["uid"] = json!("cltermux:42");
    bundle["snapshot"]["issuer"] = bundle["issuer"].clone();
    bundle["snapshot"]["uid"] = bundle["uid"].clone();
    let ciphertext = encrypt_secret(
        &secrets,
        SecretContext::ResourceServiceBindingToken {
            provider: provider_id,
            binding: binding_id,
        },
        &SecretString::new(bundle.to_string()),
    )
    .unwrap()
    .encode();
    sqlx::query(
        "UPDATE resource_service_providers SET client_secret_ciphertext = $2 WHERE id = $1",
    )
    .bind(provider_id)
    .bind(secret)
    .execute(database)
    .await
    .unwrap();
    sqlx::query("UPDATE resource_service_bindings SET token_bundle_ciphertext = $2, grant_id = $3, grant_expires_at = $4, access_expires_at = NOW() + INTERVAL '1 hour' WHERE id = $1")
        .bind(binding_id).bind(ciphertext).bind(Uuid::parse_str(bundle["grant_id"].as_str().unwrap()).unwrap())
        .bind(time::OffsetDateTime::parse(bundle["grant_expires_at"].as_str().unwrap(), &time::format_description::well_known::Rfc3339).unwrap())
        .execute(database).await.unwrap();
}

pub(super) async fn seed_provider(database: &sqlx::PgPool, slug: &str, scope: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resource_service_providers (id, slug, display_name, issuer, client_id, client_secret_ciphertext, identifier_label, secret_label, identifier_sensitive, scope, scope_description, scope_access, allowed_client_ids, enabled) VALUES ($1, $2, $2, $3, 'ap-client', 'not-decrypted', 'Account', 'Secret', FALSE, $4, '', 'restricted', $5, TRUE)")
        .bind(id).bind(slug).bind(format!("https://{slug}.example.test")).bind(scope).bind(vec![CLIENT.to_owned()]).execute(database).await.unwrap();
    id
}

pub(super) async fn set_package(env: &Env, package: Option<&str>) {
    let link = package.map(|package| json!({"package_name": package, "sha256_cert_fingerprints": ["AA:".repeat(31) + "AA"]}));
    sqlx::query("UPDATE oauth_clients SET android_asset_link = $2 WHERE client_id = $1")
        .bind(CLIENT)
        .bind(link)
        .execute(&env.database)
        .await
        .unwrap();
}

pub(super) async fn grant_scopes(env: &Env, scopes: &[&str]) {
    sqlx::query("UPDATE oauth_clients SET scopes = $2 WHERE client_id = $1")
        .bind(CLIENT)
        .bind(json!(scopes))
        .execute(&env.database)
        .await
        .unwrap();
    env.state
        .consents
        .save(
            env.user_id,
            CLIENT,
            &scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
}

pub(super) fn issuer(state: &AppState) -> String {
    state.issuer.current().unwrap().issuer().as_str().to_owned()
}

pub(super) fn token_for(env: &Env, scopes: &[&str]) -> String {
    issue_access_token(
        &env.state.keys,
        &issuer(&env.state),
        &env.user_id.to_string(),
        CLIENT,
        &scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<Vec<_>>(),
        3600,
    )
    .unwrap()
}

pub(super) fn valid_body() -> Value {
    json!({"app_kind": "chrome_termux", "device_id": "device-1"})
}

pub(super) async fn exchange(env: &Env, token: Option<&str>, body: Value) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v2/auth/chenxing/exchange")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    env.router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

pub(super) async fn raw_exchange(env: &Env, body: &str) -> Response {
    env.router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/auth/chenxing/exchange")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", env.token))
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn userinfo(env: &Env, method: &str, token: &str) -> Response {
    env.router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri("/oauth/userinfo")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn revoke(env: &Env, token: &str) -> Response {
    env.router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "client_id={CLIENT}&token={token}&token_type_hint=access_token"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) fn assert_no_store(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
}

pub(super) async fn assert_error(response: Response, status: StatusCode, code: &str) {
    assert_no_store(&response);
    assert_eq!(response.status(), status);
    let body = crate::http::json_body(response).await;
    assert_eq!(body["code"], code, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
    assert_eq!(body.as_object().unwrap().len(), 2);
}
