use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::{api, clients::domain::ClientRegistrationInput, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

use crate::oauth_flow;

async fn test_state() -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    oauth_flow::test_state("revocation_handler").await
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
        STANDARD.encode(format!(
            "{}:{}",
            client.client_id,
            client.client_secret.expect("confidential client secret")
        ))
    );

    let response = revoke(&router, &authorization, "token=unknown-token%ZZ").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_request");

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
