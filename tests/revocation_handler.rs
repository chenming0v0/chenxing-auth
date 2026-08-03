use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::{
    api, clients::domain::ClientRegistrationInput, config::Config, db,
    sqlx::postgres::PgPoolOptions, state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

async fn test_state() -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for revocation handler tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-revocation-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "revocation-test-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new(config).expect("test state");
    (state, database, key_directory)
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn revoke(router: &Router, authorization: &str, form: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", authorization)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_owned()))
                .expect("revocation request"),
        )
        .await
        .expect("revocation response")
}

#[tokio::test]
async fn revocation_handler_rejects_unknown_hint_and_accepts_supported_hints() {
    let (state, database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let client = state
        .clients
        .register(ClientRegistrationInput {
            client_name: "Revocation Handler Test Client".to_owned(),
            redirect_uris: vec!["https://revocation.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
        })
        .await
        .expect("test client");
    let authorization = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", client.client_id, client.client_secret))
    );

    let response = revoke(
        &router,
        &authorization,
        "token=unknown-token&token_type_hint=foo",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "unsupported_token_type");

    for hint in ["access_token", "refresh_token"] {
        let response = revoke(
            &router,
            &authorization,
            &format!("token=unknown-token&token_type_hint={hint}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "hint: {hint}");
    }

    let response = revoke(&router, &authorization, "token=unknown-token").await;
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client.client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}
