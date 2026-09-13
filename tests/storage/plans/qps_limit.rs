//! Plan QPS limiting and source-IP limiting without an effective plan.

use super::*;

#[tokio::test]
async fn qps_limiter_rejects_requests_over_the_plan_limit() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    // 用 1 QPS 做顺序断言：第一发进入业务校验返回 400，第二发必被滑动窗口拒绝。
    // 这比并发三连更稳，也更直接验证 token 路径真正调用了 plan-backed limiter。
    // 窗口由 `support::qps_window` 注入成 60s（生产仍是 1s），两发之间那次 19 MiB
    // Argon2 校验再慢也不会把第一发挤出窗口。
    let plan = create_plan(
        &router,
        &suffix,
        plan_limits(1, 1_000, Some(10_000), Some(1)),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("authorization", format!("Basic {basic_credentials}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .expect("token request")
    };

    let invalid_basic_credentials = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let invalid = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(
                    "authorization",
                    format!("Basic {invalid_basic_credentials}"),
                )
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code"))
                .expect("invalid credential request"),
        )
        .await
        .expect("invalid credential response");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let first = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("first token response");
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("second token response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(second).await["error"], "temporarily_unavailable");

    env.cleanup().await;
}

/// 无生效套餐时 `enforce_qps` 里的 `effective?.plan.max_qps?` early-return
/// 路径的专项覆盖。
///
/// 这条路径与 `no_default_plan_keeps_existing_user_clients_working`（authorize 路径）
/// 守同一条不变式，但在 **token 路径**上：「闸门只关新增，不打死既有集成」。
/// 如果有人把那个 `?` 改成 `unwrap_or(0)` 或返回 503，authorize 那条测试抓不到，
/// 这条测试会抓到。
#[tokio::test]
async fn no_plan_skips_plan_qps_limiting_for_existing_clients() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    // Step 1: 创建 max_qps=1 的套餐并分配给用户。
    let plan = create_plan(
        &router,
        &suffix,
        plan_limits(1, 1_000, Some(10_000), Some(1)),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    // Step 2: 建一个 user client，记录凭据。
    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));

    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("authorization", format!("Basic {basic_credentials}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .expect("token request")
    };

    // Step 3: 先证明套餐下 QPS 闸门是生效的。
    // 第一发：凭据正确、套餐 QPS 允许，进入业务校验 → 400 (code 缺失)。
    // 第二发：同一个滑动窗口内第二次 → 429。
    // 窗口由 `support::qps_window` 注入成 60s（生产仍是 1s），因此两发必然落在同一
    // 窗口内，不再取决于 token 路径上那次 19 MiB Argon2 校验跑得有多快。
    // 这一步是关键：如果套餐 QPS 本来就不生效，第 5 步的「通过」就是假绿。
    let first = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("first token response");
    assert_eq!(
        first.status(),
        StatusCode::BAD_REQUEST,
        "first request under plan must reach business logic (400 = plan QPS allowed)"
    );

    let second = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("second token response under plan");
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request in the same window must be rejected by plan QPS (429)"
    );

    // Step 4: 清空所有套餐，模拟「平台无生效套餐」场景。
    clear_all_plans(&env.database).await;

    // Step 5: 连打多发确认按套餐 QPS 已跳过，不再出现 429 或 503。
    // 不 sleep：60s 窗口让第 3 步写入的条目**必然**还活着（以前只是「可能」），
    // 所以如果有人把 `?` 改成 `unwrap_or(0)` 导致限流仍然生效，第一发就会 429
    // 并立即失败。窗口注入把这条突变检测从概率性变成确定性。
    for i in 0..3_u32 {
        let resp = router
            .clone()
            .oneshot(token_request())
            .await
            .expect("post-clear token response");
        let status = resp.status();
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} after clearing plans must NOT be plan-QPS limited (429)"
        );
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "request {i} after clearing plans must NOT return 503"
        );
        // 应当仍然进入业务校验并因缺少 code 返回 400。
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "request {i} after clearing plans must reach business logic (400)"
        );
    }

    // Step 6: 安全边界断言 —— 无套餐不等于全部限流失效。
    // 按源 IP 的 QPS 滑动窗口（`enforce_source_qps`）独立于套餐，
    // 清套餐后它必须仍然可以触发，防止有人误改成「无套餐 = 完全放行」。
    //
    // 用唯一 IP 的 ConnectInfo 通过 HTTP 路径真实调用 enforce_source_qps，
    // 预先饱和窗口后发起 HTTP 请求，验证 token_inner 仍然调用 enforce_source_qps。
    // 如果有人删掉了 enforce_source_qps 调用，此请求会进入业务逻辑返回 400，测试失败。
    // `chenxing:qps:source:{ip}` 是全局 Redis key，不受 schema 隔离保护。旧写法把
    // 整个 suffix 折叠进 203.0.113.0/24 的 254 个槽位，既丢掉测试身份也会在并发或
    // 重复运行时踩到别人的窗口。改用 IPv6 文档前缀 2001:db8::/32（RFC 3849）拼上本
    // 测试 Uuid 的低 96 位：地址与这次运行一一对应，冲突概率可以忽略。
    let uuid_tail = &suffix[suffix.len() - 24..];
    let groups: Vec<&str> = (0..6).map(|i| &uuid_tail[i * 4..i * 4 + 4]).collect();
    let fake_ip: IpAddr = format!("2001:db8:{}", groups.join(":"))
        .parse()
        .expect("valid IPv6 test address");
    // 限流 key 用 `IpAddr::to_string()` 的规范形式，必须和 handler 侧
    // （`api::source_ip` → `resolve_client_ip`）算出的字符串逐字节一致。
    let fake_ip_str = fake_ip.to_string();

    // 预先饱和该 IP 的源 QPS 窗口（默认限制 30）。
    let source_qps_limit = env.state.config.security_limits.unauthenticated_source_qps;
    for _ in 0..source_qps_limit {
        env.state
            .qps
            .allow_source(&fake_ip_str, source_qps_limit)
            .await
            .expect("pre-saturate source window");
    }

    // 现在用该 IP 发起 HTTP 请求，handler 会调用 enforce_source_qps 发现窗口已满 → 429。
    let saturated_request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("authorization", format!("Basic {basic_credentials}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .extension(ConnectInfo(SocketAddr::new(fake_ip, 12345)))
        .body(Body::from("grant_type=authorization_code"))
        .expect("source-ip-saturated token request");

    let source_limited = router
        .clone()
        .oneshot(saturated_request)
        .await
        .expect("source-limited response");
    assert_eq!(
        source_limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "enforce_source_qps must still trigger (429) after clearing plans"
    );

    env.cleanup().await;
}
