//! 拆分自 `request_rebinding.rs`：holder Cookie 所有权、幂等重绑、并发收敛、
//! legacy holder hash 与 issuer 代际切换场景。

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{
    sessions::domain::session_token_hash, settings::issuer::IssuerRecord, state::AppState,
};
use tower::ServiceExt;

use crate::http;

use super::request_rebinding::{
    REDIRECT_URI_ENCODED, bind, cleanup, create_client, create_user, inspect, persisted_session,
    request_id, session_cookie, set_cookie_pair, setup, start_unauthenticated_authorization,
};

fn switch_issuer_generation(state: &AppState) -> i64 {
    let current = state.issuer.current().expect("current issuer");
    let next_generation = current.generation() + 1;
    state
        .issuer
        .apply(&IssuerRecord {
            value: "http://127.0.0.1:3999".to_owned(),
            generation: next_generation,
            updated_at: state.clock.now(),
        })
        .expect("apply next issuer generation");
    next_generation
}

/// 安全边界不变：没有 holder Cookie 的第三方账号即使持有有效会话也不能重绑，
/// 且被拒的尝试不得改动已有绑定。这是重绑语义安全性的核心断言。
#[tokio::test]
async fn third_party_session_without_holder_cookie_cannot_rebind() {
    let (router, state, database, key_directory) = setup().await;
    let victim = create_user(&router, "rebind-victim").await;
    let attacker = create_user(&router, "rebind-attacker").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let victim_session = persisted_session(&state, victim).await;
    let victim_cookie = format!("{}; {holder}", session_cookie(&victim_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &victim_cookie,
            &victim_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 攻击者拿到泄露的 request_id，持有自己的有效会话，但没有 holder Cookie。
    let attacker_session = persisted_session(&state, attacker).await;
    let attacker_cookie = session_cookie(&attacker_session);
    assert_eq!(
        bind(
            &router,
            &request_id,
            &attacker_cookie,
            &attacker_session.csrf_token
        )
        .await,
        StatusCode::FORBIDDEN,
        "a valid session without the holder cookie must never claim a pending request"
    );

    // 伪造的 holder 同样被拒。
    let forged_cookie = format!("{attacker_cookie}; chenxing_authz_holder=forged-holder-value");
    assert_eq!(
        bind(
            &router,
            &request_id,
            &forged_cookie,
            &attacker_session.csrf_token
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // 受害者的绑定完好无损。
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&victim_session.token).as_str())
    );
    assert_eq!(
        inspect(&router, &request_id, &attacker_cookie).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        inspect(&router, &request_id, &victim_cookie).await,
        StatusCode::OK
    );

    cleanup(&database, &client_id, &[victim, attacker], key_directory).await;
}

/// 已登录用户首次授权也必须拿到 holder Cookie（#270）。
///
/// 否则这条路径创建的 pending 请求永远无法重绑：会话在确认前过期后，用户
/// 只能在登录页与确认页之间打转。
#[tokio::test]
async fn authenticated_consent_redirect_issues_holder_cookie_and_supports_rebinding() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-authenticated").await;
    let client_id = create_client(&router).await;

    // 已登录浏览器直接命中 authorize：应重定向到确认页并下发 holder。
    let first_session = persisted_session(&state, user_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI_ENCODED}&response_type=code&scope=openid%20profile&state=rebind-authenticated-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
                ))
                .header("accept", "text/html")
                .header("cookie", session_cookie(&first_session))
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    let target = http::location(&response);
    assert!(
        target.starts_with("/oauth/consent?"),
        "an authenticated first-time authorization must land on the consent page, got {target}"
    );
    let holder = set_cookie_pair(&response, "chenxing_authz_holder").expect(
        "the authenticated consent redirect must also issue the holder cookie so the request stays rebindable (#270)",
    );
    let request_id = request_id(&target);

    // 会话在确认前过期，用户重新登录：新会话仍能重绑并继续。
    state
        .sessions
        .revoke(&first_session.token)
        .await
        .expect("revoke session");
    let second_session = persisted_session(&state, user_id).await;
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// 幂等：同一会话重复绑定返回 204 且不改动载荷；请求被消费后绑定按过期处理。
#[tokio::test]
async fn repeated_bind_is_idempotent_and_consumed_request_reports_expired() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-idempotent").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let session = persisted_session(&state, user_id).await;
    let cookie = format!("{}; {holder}", session_cookie(&session));
    for _ in 0..3 {
        assert_eq!(
            bind(&router, &request_id, &cookie, &session.csrf_token).await,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&session.token).as_str())
    );

    // 消费掉请求（拒绝），之后的绑定必须是 400 过期，而不是 401/403 或静默成功。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"deny"}"#))
                .expect("deny request"),
        )
        .await
        .expect("deny response");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        bind(&router, &request_id, &cookie, &session.csrf_token).await,
        StatusCode::BAD_REQUEST
    );
    assert!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find consumed request")
            .is_none(),
        "a failed bind must not resurrect a consumed pending request"
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

#[tokio::test]
async fn concurrent_bind_requests_converge_to_one_session() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-concurrent").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let first_session = persisted_session(&state, user_id).await;
    let second_session = persisted_session(&state, user_id).await;
    let first_cookie = format!("{}; {holder}", session_cookie(&first_session));
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    let (first, second) = tokio::join!(
        bind(
            &router,
            &request_id,
            &first_cookie,
            &first_session.csrf_token,
        ),
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token,
        ),
    );
    assert_eq!(first, StatusCode::NO_CONTENT);
    assert_eq!(second, StatusCode::NO_CONTENT);

    let stored = state
        .authorization_requests
        .find(&request_id)
        .await
        .expect("find pending request")
        .expect("pending request exists")
        .session_token_hash
        .expect("bound session hash");
    assert!(
        stored == session_token_hash(&first_session.token)
            || stored == session_token_hash(&second_session.token),
        "concurrent CAS updates must leave exactly one complete session hash"
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

#[tokio::test]
async fn legacy_pending_request_without_holder_hash_is_rejected() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-legacy-holder").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let pending = state
        .authorization_requests
        .find(&request_id)
        .await
        .expect("find pending request")
        .expect("pending request exists");
    let mut legacy = pending.clone();
    legacy.holder_hash = None;
    assert!(
        state
            .authorization_requests
            .replace_if_matches(&request_id, &pending, &legacy)
            .await
            .expect("replace pending request")
    );

    let session = persisted_session(&state, user_id).await;
    let cookie = format!("{}; {holder}", session_cookie(&session));
    assert_eq!(
        bind(&router, &request_id, &cookie, &session.csrf_token).await,
        StatusCode::FORBIDDEN,
        "records created before holder binding support must fail secure"
    );
    let stored = state
        .authorization_requests
        .find(&request_id)
        .await
        .expect("find rejected pending request")
        .expect("pending request remains");
    assert!(stored.holder_hash.is_none());
    assert!(stored.session_token_hash.is_none());

    state
        .authorization_requests
        .take(&request_id)
        .await
        .expect("cleanup pending request");
    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// Issue #523: every continuation of a pending authorization stays in the
/// issuer generation captured by the original `/oauth/authorize` request.
#[tokio::test]
async fn issuer_change_expires_pending_requests_before_bind_inspect_or_decide() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-issuer-generation").await;
    let client_id = create_client(&router).await;
    let session = persisted_session(&state, user_id).await;
    let issuer_a = state.issuer.current().expect("issuer A");

    let mut requests = Vec::new();
    for _ in 0..3 {
        let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;
        let cookie = format!("{}; {holder}", session_cookie(&session));
        assert_eq!(
            bind(&router, &request_id, &cookie, &session.csrf_token).await,
            StatusCode::NO_CONTENT
        );
        let stored = state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("load issuer-bound pending request")
            .expect("pending request exists");
        assert_eq!(stored.issuer_generation, Some(issuer_a.generation()));
        requests.push((request_id, cookie));
    }

    let issuer_b_generation = switch_issuer_generation(&state);
    assert_ne!(issuer_b_generation, issuer_a.generation());

    assert_eq!(
        bind(&router, &requests[0].0, &requests[0].1, &session.csrf_token).await,
        StatusCode::BAD_REQUEST,
        "an A-era pending request must not bind under issuer B"
    );
    assert_eq!(
        inspect(&router, &requests[1].0, &requests[1].1).await,
        StatusCode::BAD_REQUEST,
        "an A-era pending request must not be inspected under issuer B"
    );

    let decision = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{}",
                    requests[2].0
                ))
                .header("cookie", &requests[2].1)
                .header("x-csrf-token", &session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve stale issuer request"),
        )
        .await
        .expect("stale issuer decision response");
    assert_eq!(
        decision.status(),
        StatusCode::BAD_REQUEST,
        "an A-era pending request must not issue a B-era authorization code"
    );

    for (request_id, _) in &requests {
        assert!(
            state
                .authorization_requests
                .find(request_id)
                .await
                .expect("reload rejected pending request")
                .is_none(),
            "issuer-mismatched pending requests must be discarded"
        );
    }

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}
