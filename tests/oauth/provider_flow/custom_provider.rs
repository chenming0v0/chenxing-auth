//! Split from `provider_flow.rs` (nested child module).

use super::*;

#[tokio::test]
async fn custom_provider_registers_reuses_identity_and_rejects_state_replay() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_location = http::location(&response);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("mock client")
        .get(&authorize_location)
        .send()
        .await
        .expect("mock authorize");
    assert_eq!(authorize_response.status(), reqwest::StatusCode::SEE_OTHER);
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("mock callback location")
        .to_owned();
    let callback = url::Url::parse(&callback_location).expect("callback URL");
    let state = callback
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&response).contains("external=success"),
        "unexpected callback location: {}",
        http::location(&response)
    );
    let first_session = set_cookie(&response, "chenxing_session=");
    let count: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(count.0, 1);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("second start"),
        )
        .await
        .expect("second start response");
    let second_state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let second_location = http::location(&response);
    let second_authorize = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("mock client")
        .get(&second_location)
        .send()
        .await
        .expect("second authorize");
    let second_callback = second_authorize
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("second callback location")
        .to_owned();
    let second_state = url::Url::parse(&second_callback)
        .expect("second callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("second state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("second callback request"),
        )
        .await
        .expect("second callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie(&response, "chenxing_session=") != first_session);
    let count: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("user count");
    assert_eq!(count.0, 1);
    let password_login_enabled: (bool,) =
        chenxing_auth::sqlx::query_as("SELECT password_login_enabled FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("external user password login flag");
    assert!(!password_login_enabled.0);

    let token_form = mock_state
        .token_form
        .lock()
        .await
        .clone()
        .expect("token form");
    // RFC 7636 §4.5：token 请求必须带上 code_verifier，把授权码绑定到本次授权会话。
    // verifier 是随机值，先取出后单独校验，再比对其余字段的精确集合。
    let code_verifier = token_form
        .get("code_verifier")
        .expect("token 请求必须包含 code_verifier")
        .clone();
    assert!(
        (43..=128).contains(&code_verifier.len()),
        "code_verifier 长度必须符合 RFC 7636 §4.1: {}",
        code_verifier.len()
    );
    assert!(
        code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
        "code_verifier 必须只含 RFC 7636 unreserved 字符: {code_verifier}"
    );
    // 授权请求里发出的 challenge 必须等于 S256(verifier)。
    let sent_challenge = authorization_query(&second_location, "code_challenge")
        .expect("授权请求必须包含 code_challenge");
    assert_eq!(
        authorization_query(&second_location, "code_challenge_method").as_deref(),
        Some("S256"),
        "code_challenge_method 必须是 S256"
    );
    assert_eq!(
        sent_challenge,
        s256_challenge(&code_verifier),
        "code_challenge 必须等于 BASE64URL(SHA256(code_verifier))"
    );
    let expected_form = HashMap::from([
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), "mock-code".to_owned()),
        (
            "redirect_uri".to_owned(),
            format!("http://127.0.0.1:3000/auth/external/{slug}/callback"),
        ),
        ("client_id".to_owned(), "mock-client".to_owned()),
        ("client_secret".to_owned(), "mock-secret".to_owned()),
        ("code_verifier".to_owned(), code_verifier),
    ]);
    assert_eq!(token_form, expected_form);

    let replay = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("replay request"),
        )
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert!(http::location(&replay).contains("external_error=oauth_login_failed"));
    let replay_state_cookie_name = second_state_cookie
        .split_once('=')
        .map(|(name, _)| name)
        .expect("replay state cookie name");
    assert!(
        set_cookie_header(&replay, &format!("{replay_state_cookie_name}=")).contains("Max-Age=0"),
        "a replayed state must clear its stale browser state cookie"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn custom_provider_does_not_auto_link_existing_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let registration = serde_json::json!({
        "username": format!("local-{}", Uuid::new_v4().simple()),
        "email": external_email,
        "password": "local-password-123",
        "display_name": "Local Person"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(registration.to_string()))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(registration.to_string()))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("mock client")
        .get(http::location(&response))
        .send()
        .await
        .expect("mock authorize");
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("callback location");
    let state = url::Url::parse(callback_location)
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(http::location(&response).contains("external_error=oauth_account_link_required"));

    let identities: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(identities.0, 0);
    let _ = std::fs::remove_dir_all(key_directory);
}
