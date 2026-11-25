use super::*;

#[tokio::test]
async fn disabled_200_snapshot_is_saved_after_portal_session_revocation() {
    let bound = bind_live("disabled-200-session").await;
    *bound.env.stub.revoke_session_on_account.lock().unwrap() = Some(bound.session_id);
    bound.env.stub.set_account(Script::DisabledSnapshot);
    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_eq!(row.status.as_deref(), Some("disabled"));
    assert!(row.live);
    assert!(row.has_ciphertext);
}

#[tokio::test]
async fn restored_active_snapshot_is_saved_after_portal_session_revocation() {
    let bound = bind_live("restored-session").await;
    chenxing_auth::sqlx::query("UPDATE resource_service_bindings SET snapshot_json = jsonb_set(snapshot_json, '{status}', '\"disabled\"') WHERE id = $1")
        .bind(bound.binding_id).execute(&bound.env.database).await.unwrap();
    *bound.env.stub.revoke_session_on_account.lock().unwrap() = Some(bound.session_id);
    bound.env.stub.set_account(Script::Ok);
    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        stored_snapshot(&bound.env.database, bound.binding_id)
            .await
            .status
            .as_deref(),
        Some("active")
    );
}

#[tokio::test]
async fn provider_update_metadata_does_not_hold_provider_lock() {
    let bound = bind_live("metadata-lock").await;
    let provider_id = binding_provider_id(&bound.env.database, bound.binding_id).await;
    bound
        .env
        .stub
        .check_metadata_lock
        .store(true, Ordering::SeqCst);
    let response = bound.env.router.clone().oneshot(Request::builder()
        .method("PUT").uri(format!("/api/v1/admin/resource-services/{provider_id}"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"slug":"demo","display_name":"Renamed service","issuer":PROVIDER_ISSUER,"client_id":"chenxing-portal","scope":SCOPE,"scope_description":"read demo account","scope_access":"public","expected_revision":1}).to_string())).unwrap())
        .await.unwrap();
    let status = response.status();
    let body = http::json_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

struct ReorderedProvider {
    inner: Arc<StubProvider>,
    calls: AtomicUsize,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

struct RefreshOverlapProvider {
    inner: Arc<StubProvider>,
    refresh_entered: tokio::sync::Semaphore,
    refresh_release: tokio::sync::Semaphore,
    account_entered: tokio::sync::Semaphore,
    account_release: tokio::sync::Semaphore,
}

impl ProviderTransport for RefreshOverlapProvider {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            if request.url.path().ends_with("/refresh") {
                self.refresh_entered.add_permits(1);
                self.refresh_release.acquire().await.unwrap().forget();
                return self.inner.execute(request).await;
            }
            if request.url.path() == "/api/v1/account-provider/account" {
                self.account_entered.add_permits(1);
                self.account_release.acquire().await.unwrap().forget();
                return scripted(Script::DisabledSnapshot, account_ok());
            }
            self.inner.execute(request).await
        })
    }
}

#[tokio::test]
async fn newer_disabled_query_survives_earlier_token_rotation() {
    let mut bound = bind_live("newer-query-rotation").await;
    let stub = Arc::new(RefreshOverlapProvider {
        inner: bound.env.stub.clone(),
        refresh_entered: tokio::sync::Semaphore::new(0),
        refresh_release: tokio::sync::Semaphore::new(0),
        account_entered: tokio::sync::Semaphore::new(0),
        account_release: tokio::sync::Semaphore::new(0),
    });
    bound.env.state.resource_services = bound
        .env
        .state
        .resource_services
        .clone()
        .with_transport_override(stub.clone());
    bound.env.router = api::router(bound.env.state.clone());
    let router = bound.env.router.clone();
    let cookie = bound.cookie.clone();
    let csrf = bound.csrf.clone();
    let binding_id = bound.binding_id;
    let refresh =
        tokio::spawn(async move { post_refresh(&router, &cookie, &csrf, binding_id).await });
    stub.refresh_entered.acquire().await.unwrap().forget();
    let router = bound.env.router.clone();
    let cookie = bound.cookie.clone();
    let csrf = bound.csrf.clone();
    let sync = tokio::spawn(async move { post_sync(&router, &cookie, &csrf, binding_id).await });
    stub.account_entered.acquire().await.unwrap().forget();
    stub.refresh_release.add_permits(1);
    assert_eq!(refresh.await.unwrap().status(), StatusCode::OK);
    stub.account_release.add_permits(1);
    assert_eq!(sync.await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        stored_snapshot(&bound.env.database, binding_id)
            .await
            .status
            .as_deref(),
        Some("disabled")
    );
}

impl ProviderTransport for ReorderedProvider {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            if request.url.path() == "/api/v1/account-provider/account" {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.entered.add_permits(1);
                    self.release.acquire().await.unwrap().forget();
                    return scripted(Script::DisabledSnapshot, account_ok());
                }
                return Ok(account_ok());
            }
            self.inner.execute(request).await
        })
    }
}

#[tokio::test]
async fn delayed_disabled_reply_does_not_overwrite_newer_active_query() {
    let mut bound = bind_live("reordered-snapshot").await;
    let stub = Arc::new(ReorderedProvider {
        inner: bound.env.stub.clone(),
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    bound.env.state.resource_services = bound
        .env
        .state
        .resource_services
        .clone()
        .with_transport_override(stub.clone());
    bound.env.router = api::router(bound.env.state.clone());
    let router = bound.env.router.clone();
    let cookie = bound.cookie.clone();
    let csrf = bound.csrf.clone();
    let binding_id = bound.binding_id;
    let old = tokio::spawn(async move { post_sync(&router, &cookie, &csrf, binding_id).await });
    stub.entered.acquire().await.unwrap().forget();
    assert_eq!(
        post_sync(&bound.env.router, &bound.cookie, &bound.csrf, binding_id)
            .await
            .status(),
        StatusCode::OK
    );
    stub.release.add_permits(1);
    old.await.unwrap();
    assert_eq!(
        stored_snapshot(&bound.env.database, binding_id)
            .await
            .status
            .as_deref(),
        Some("active")
    );
}
