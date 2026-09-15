//! Split from `request_rebinding.rs` (nested child module).

use super::*;

#[tokio::test]
async fn max_age_zero_rejects_the_old_session_and_accepts_a_new_login_session() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "max-age-zero").await;
    let client_id = create_client(&router).await;
    grant_consent(&database, user_id, &client_id).await;
    let old_session = persisted_session(&state, user_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?{}",
                    authorize_query(&client_id, "&prompt=login&max_age=0")
                ))
                .header("accept", "text/html")
                .header("cookie", session_cookie(&old_session))
                .body(Body::empty())
                .expect("max_age=0 authorize request"),
        )
        .await
        .expect("max_age=0 authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = http::location(&response);
    assert!(target.starts_with("/login?request_id="));
    let request_id = request_id(&target);
    let holder = set_cookie_pair(&response, "chenxing_authz_holder")
        .expect("reauthentication redirect must issue holder cookie");

    let old_cookie = format!("{}; {holder}", session_cookie(&old_session));
    assert_eq!(
        bind(&router, &request_id, &old_cookie, &old_session.csrf_token).await,
        StatusCode::NO_CONTENT
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &old_cookie)
                .header("x-csrf-token", &old_session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("old-session approval request"),
        )
        .await
        .expect("old-session approval response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(http::json_body(response).await["code"], "login_required");

    let new_session = persisted_session(&state, user_id).await;
    let new_cookie = format!("{}; {holder}", session_cookie(&new_session));
    assert_eq!(
        bind(&router, &request_id, &new_cookie, &new_session.csrf_token).await,
        StatusCode::NO_CONTENT
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &new_cookie)
                .header("x-csrf-token", &new_session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("new-session approval request"),
        )
        .await
        .expect("new-session approval response");
    assert_eq!(response.status(), StatusCode::OK);
    let redirect = http::json_body(response).await["redirect_to"]
        .as_str()
        .expect("authorization redirect")
        .to_owned();
    let code_value = callback_parameter(&redirect, "code").expect("authorization code");
    let code = state
        .authorization_codes
        .find(&code_value)
        .await
        .expect("load authorization code")
        .expect("stored authorization code");
    assert_eq!(
        code.session_token_hash.as_deref(),
        Some(session_token_hash(&new_session.token).as_str())
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// 会话过期恢复：绑定 → 会话撤销 → 重新登录得到新会话 → 同一 holder 重绑成功。
///
/// 旧行为在最后一步固定 `401 invalid_session`，前端据此跳登录页，形成循环。
#[tokio::test]
async fn expired_session_rebinds_after_relogin_and_can_still_approve() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-expiry").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    // 第一次登录：绑定成功。
    let first_session = persisted_session(&state, user_id).await;
    let first_cookie = format!("{}; {holder}", session_cookie(&first_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &first_cookie,
            &first_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 会话过期 / 被撤销：pending 记录里仍留着旧会话摘要。
    state
        .sessions
        .revoke(&first_session.token)
        .await
        .expect("revoke first session");

    // 重新登录得到全新会话，holder Cookie 仍在浏览器里（TTL 与 pending 对齐）。
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
        StatusCode::NO_CONTENT,
        "a fresh session with a valid holder cookie must be able to rebind (#270)"
    );

    // 重绑后的会话摘要必须指向新会话：授权码会继承这个绑定。
    let pending = state
        .authorization_requests
        .find(&request_id)
        .await
        .expect("find pending request")
        .expect("pending request still exists");
    assert_eq!(
        pending.session_token_hash.as_deref(),
        Some(session_token_hash(&second_session.token).as_str())
    );

    // 新会话可以读取并批准，流程真正恢复而不只是 bind 返回 204。
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &second_cookie)
                .header("x-csrf-token", &second_session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve request"),
        )
        .await
        .expect("approve response");
    assert_eq!(response.status(), StatusCode::OK);
    let approved = http::json_body(response).await;
    assert!(
        approved["redirect_to"]
            .as_str()
            .is_some_and(|value| value.contains("code=")),
        "approval after rebinding must issue an authorization code"
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// 切换账号：同一浏览器登出后换另一个账号登录，pending 请求重绑到新账号会话。
///
/// 这是「使用其他辰星通行证」的正常流程，不是攻击：holder 证明还是同一个浏览器。
#[tokio::test]
async fn account_switch_rebinds_pending_request_to_the_second_account() {
    let (router, state, database, key_directory) = setup().await;
    let first_user = create_user(&router, "rebind-switch-a").await;
    let second_user = create_user(&router, "rebind-switch-b").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let first_session = persisted_session(&state, first_user).await;
    let first_cookie = format!("{}; {holder}", session_cookie(&first_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &first_cookie,
            &first_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 切换账号：第二个用户在同一浏览器登录（holder Cookie 不变）。
    let second_session = persisted_session(&state, second_user).await;
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT,
        "switching accounts in the same browser must rebind, not deadlock (#270)"
    );
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&second_session.token).as_str())
    );

    // 第一个账号的会话此时不再持有该请求：读取被拒，不能替第二个账号做决定。
    assert_eq!(
        inspect(&router, &request_id, &first_cookie).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );

    cleanup(
        &database,
        &client_id,
        &[first_user, second_user],
        key_directory,
    )
    .await;
}
