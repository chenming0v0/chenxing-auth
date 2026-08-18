use axum::{
    body::Body,
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, PRAGMA, SET_COOKIE},
    },
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};
use totp_rs::TOTP;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

#[path = "support/oauth_flow.rs"]
mod support;

use support::{create_test_client, ensure_owner_bootstrapped, json_body, test_router};

const TEST_ORIGIN: &str = "http://127.0.0.1:3000/";

fn resolve_location(location: &str) -> Url {
    Url::parse(TEST_ORIGIN)
        .expect("test origin")
        .join(location)
        .expect("valid redirect location")
}

fn assert_token_cache_headers(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("JWT payload encoding");
    serde_json::from_slice(&payload).expect("JWT claims")
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
async fn browser_oauth_code_flow_reaches_userinfo_and_refresh_with_no_store_headers() {
    let (router, database, key_directory) = test_router("oauth_token_flow").await;
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_token_flow", &suffix).await;
    let email = format!("flow-{suffix}@example.com");
    let username = format!("flow-{suffix}");
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
                        "username": username,
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["code"], "registration_disabled");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "display_name": "Flow User"
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json_body(response).await;
    let user_id = user["id"].as_i64().expect("numeric user id");

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
    let (form_client_id, form_client_secret) =
        create_test_client(&router, "flow-admin-token").await;
    chenxing_auth::sqlx::query(
        "UPDATE oauth_clients SET auth_method = 'client_secret_post' WHERE client_id = $1",
    )
    .bind(&form_client_id)
    .execute(&database)
    .await
    .expect("enable form client authentication");

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
                .body(Body::from(
                    serde_urlencoded::to_string([
                        ("token", "unknown-token"),
                        ("client_id", form_client_id.as_str()),
                        ("client_secret", form_client_secret.as_str()),
                    ])
                    .expect("form revocation encoding"),
                ))
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
                    serde_json::json!({"identifier": username, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookie = cookie_header(&response);
    assert!(session_cookie.contains("chenxing_session="));
    assert!(session_cookie.contains("chenxing_csrf="));
    let csrf = session_cookie
        .split(';')
        .find_map(|value| value.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned();
    assert!(json_body(response).await["expires_at"].as_str().is_some());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/start")
                .header("content-type", "application/json")
                .header("cookie", &session_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(serde_json::json!({}).to_string()))
                .expect("TOTP setup request"),
        )
        .await
        .expect("TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let enrollment_id = setup["enrollment_id"].as_str().expect("enrollment id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/confirm")
                .header("content-type", "application/json")
                .header("cookie", &session_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": enrollment_id,
                        "code": totp.generate_current().expect("TOTP code")
                    })
                    .to_string(),
                ))
                .expect("TOTP confirmation request"),
        )
        .await
        .expect("TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);

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
                .method("POST")
                .uri("/oauth/authorize")
                .header("cookie", &session_cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "client_id={client_id}&redirect_uri=https%3A%2F%2Fflow.example%2Fcallback&response_type=code&scope=openid+profile+email&state=flow-post-state&nonce=flow-post-nonce&code_challenge={challenge}&code_challenge_method=S256"
                )))
                .expect("POST authorize request"),
        )
        .await
        .expect("POST authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("/oauth/consent?request_id="))
    );
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
        .expect("authorization redirect")
        .to_owned();
    let consent_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(location.as_str())
                .body(Body::empty())
                .expect("consent SPA request"),
        )
        .await
        .expect("consent SPA response");
    assert_eq!(consent_response.status(), StatusCode::OK);
    assert_eq!(
        consent_response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );

    let consent_url = resolve_location(&location);
    assert_eq!(consent_url.path(), "/oauth/consent");
    let request_id = consent_url
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("authorization request id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookie)
                .body(Body::empty())
                .expect("inspect consent request"),
        )
        .await
        .expect("inspect consent response");
    assert_eq!(response.status(), StatusCode::OK);
    let consent = json_body(response).await;
    assert_eq!(consent["request_id"].as_str(), Some(request_id.as_str()));
    assert_eq!(consent["client_id"].as_str(), Some(client_id.as_str()));

    let csrf = session_cookie
        .split(';')
        .find_map(|value| value.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve consent request"),
        )
        .await
        .expect("approve consent response");
    assert_eq!(response.status(), StatusCode::OK);
    let decision = json_body(response).await;
    assert_eq!(decision["decision"].as_str(), Some("approve"));
    let redirect = resolve_location(
        decision["redirect_to"]
            .as_str()
            .expect("authorization redirect target"),
    );
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
    assert_token_cache_headers(&response);
    let token = json_body(response).await;
    let access_token = token["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let initial_id_token = token["id_token"].as_str().expect("initial ID token");
    assert_eq!(jwt_claims(initial_id_token)["nonce"], "flow-nonce");
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
    let user_id_text = user_id.to_string();
    assert_eq!(userinfo["sub"].as_str(), Some(user_id_text.as_str()));
    assert_eq!(userinfo["email"].as_str(), Some(email.as_str()));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/userinfo")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={access_token}")))
                .expect("form userinfo request"),
        )
        .await
        .expect("form userinfo response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["sub"].as_str(),
        Some(user_id_text.as_str())
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={access_token}")))
                .expect("conflicting userinfo request"),
        )
        .await
        .expect("conflicting userinfo response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_request");

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
    assert_token_cache_headers(&response);
    let refreshed = json_body(response).await;
    assert!(refreshed["access_token"].as_str().is_some());
    let refreshed_id_token = refreshed["id_token"].as_str().expect("refreshed ID token");
    assert!(jwt_claims(refreshed_id_token).get("nonce").is_none());
    let rotated_refresh_token = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();

    let csrf = session_cookie
        .split(';')
        .find_map(|value| value.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/authorized-apps/{client_id}"))
                .header("cookie", &session_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("consent revoke request"),
        )
        .await
        .expect("consent revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic_credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={rotated_refresh_token}"
                )))
                .expect("revoked refresh request"),
        )
        .await
        .expect("revoked refresh response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_grant");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("revoked consent userinfo request"),
        )
        .await
        .expect("revoked consent userinfo response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

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
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(form_client_id)
        .execute(&database)
        .await
        .expect("cleanup form client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
