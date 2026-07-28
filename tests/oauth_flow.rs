use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

async fn test_router() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for OAuth flow tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-flow-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "flow-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new(config).expect("test state");
    (api::router(state), database, key_directory)
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

fn cookie_header(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie value"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn browser_oauth_code_flow_reaches_userinfo_and_refresh() {
    let (router, database, key_directory) = test_router().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("flow-{suffix}@example.com");
    let password = "correct horse battery";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password,
                        "display_name": "Flow User"
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json_body(response).await;
    let user_id = user["user"]["id"].as_str().expect("user id").to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Flow Client",
                        "redirect_uris": ["https://flow.example/callback"],
                        "scopes": ["openid", "profile", "email"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client = json_body(response).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();

    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "token=unknown-token&token_type_hint=access_token",
                ))
                .expect("revocation request"),
        )
        .await
        .expect("revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let invalid_basic = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {invalid_basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=unknown-token"))
                .expect("invalid revocation request"),
        )
        .await
        .expect("invalid revocation response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token=unknown-token&client_id={client_id}&client_secret={client_secret}"
                )))
                .expect("form revocation request"),
        )
        .await
        .expect("form revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookie = cookie_header(&response);
    assert!(session_cookie.contains("chenxing_session="));
    assert!(session_cookie.contains("chenxing_csrf="));

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorize_url =
        Url::parse("http://127.0.0.1:3000/oauth/authorize").expect("authorize URL");
    authorize_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://flow.example/callback")
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email")
        .append_pair("state", "flow-state")
        .append_pair("nonce", "flow-nonce")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_url.as_str())
                .header("cookie", &session_cookie)
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let redirect = Url::parse(location).expect("redirect URL");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value),
        Some("flow-state".into())
    );

    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fflow.example%2Fcallback&code_verifier={}",
        code, verifier,
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response).await;
    let access_token = token["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    assert!(token["id_token"].as_str().is_some());
    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("userinfo request"),
        )
        .await
        .expect("userinfo response");
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo = json_body(response).await;
    assert_eq!(userinfo["sub"].as_str(), Some(user_id.as_str()));
    assert_eq!(userinfo["email"].as_str(), Some(email.as_str()));

    let refresh_form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        refresh_token, client_id, client_secret,
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(refresh_form.replace(
                    &format!("&client_id={client_id}&client_secret={client_secret}"),
                    "",
                )))
                .expect("refresh request"),
        )
        .await
        .expect("refresh response");
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response).await;
    assert!(refreshed["access_token"].as_str().is_some());
    assert!(refreshed["refresh_token"].as_str().is_some());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={access_token}")))
                .expect("access token revocation request"),
        )
        .await
        .expect("access token revocation response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("revoked userinfo request"),
        )
        .await
        .expect("revoked userinfo response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let csrf = session_cookie
        .split(';')
        .find_map(|value| value.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned();
    let response = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .header("cookie", &session_cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("session revoke request"),
        )
        .await
        .expect("session revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&user_id).expect("user UUID"))
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
