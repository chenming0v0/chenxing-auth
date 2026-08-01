use super::*;

#[tokio::test]
async fn concurrent_external_logins_keep_state_cookies_isolated() {
    let (mock, _mock_state) = mock_server().await;
    let (router, _database, key_directory, slug) = setup(mock).await;

    let first_start = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("first start request"),
        )
        .await
        .expect("first start response");
    let first_cookie_header = set_cookie_header(&first_start, EXTERNAL_STATE_COOKIE_PREFIX);
    assert!(first_cookie_header.contains("HttpOnly"));
    assert!(first_cookie_header.contains("SameSite=Lax"));
    assert!(first_cookie_header.contains("Max-Age=600"));
    assert!(first_cookie_header.contains(&format!("Path=/auth/external/{slug}/callback")));
    let first_cookie = set_cookie(&first_start, EXTERNAL_STATE_COOKIE_PREFIX);
    let first_state = authorization_state(&location(&first_start));

    let second_start = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("second start request"),
        )
        .await
        .expect("second start response");
    let second_cookie = set_cookie(&second_start, EXTERNAL_STATE_COOKIE_PREFIX);
    let second_state = authorization_state(&location(&second_start));
    assert_ne!(
        first_cookie.split('=').next(),
        second_cookie.split('=').next()
    );

    let browser_cookies = format!("{first_cookie}; {second_cookie}");
    let first_callback = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={first_state}"
                ))
                .header("cookie", &browser_cookies)
                .body(Body::empty())
                .expect("first callback request"),
        )
        .await
        .expect("first callback response");
    assert_eq!(first_callback.status(), StatusCode::SEE_OTHER);
    assert!(location(&first_callback).contains("external=success"));

    let first_cookie_name = first_cookie.split('=').next().expect("first cookie name");
    let first_clear = set_cookie_header(&first_callback, &format!("{first_cookie_name}="));
    assert!(first_clear.contains("Max-Age=0"));
    assert!(first_clear.contains(&format!("Path=/auth/external/{slug}/callback")));

    let second_callback = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &browser_cookies)
                .body(Body::empty())
                .expect("second callback request"),
        )
        .await
        .expect("second callback response");
    assert_eq!(second_callback.status(), StatusCode::SEE_OTHER);
    assert!(location(&second_callback).contains("external=success"));

    let second_cookie_name = second_cookie.split('=').next().expect("second cookie name");
    let second_clear = set_cookie_header(&second_callback, &format!("{second_cookie_name}="));
    assert!(second_clear.contains("Max-Age=0"));
    assert!(second_clear.contains(&format!("Path=/auth/external/{slug}/callback")));

    let _ = std::fs::remove_dir_all(key_directory);
}
