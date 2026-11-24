use super::*;
use chenxing_auth::resource_services::{
    ProviderHttpRequest, ProviderTransport, TransportError, TransportFuture,
};
use std::sync::atomic::Ordering;
use std::sync::{Arc, atomic::AtomicUsize};

async fn snapshot_status(env: &Env) -> String {
    sqlx::query_scalar(
        "SELECT snapshot_json->>'status' FROM resource_service_bindings WHERE id = $1",
    )
    .bind(env.binding_id)
    .fetch_one(&env.database)
    .await
    .unwrap()
}

#[tokio::test]
async fn disabled_cache_can_recover_during_exchange_without_manual_sync() {
    let env = setup().await;
    sqlx::query("UPDATE resource_service_bindings SET snapshot_json = '{\"status\":\"disabled\"}' WHERE id = $1")
        .bind(env.binding_id).execute(&env.database).await.unwrap();
    *env.stub.mode.lock().unwrap() = Some("active");
    let response = exchange(&env, Some(&env.token), valid_body()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(snapshot_status(&env).await, "active");
    assert_eq!(env.stub.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn both_disabled_response_shapes_update_cache_and_refuse_ticket() {
    for mode in ["disabled", "403"] {
        let env = setup().await;
        *env.stub.mode.lock().unwrap() = Some(mode);
        assert_error(
            exchange(&env, Some(&env.token), valid_body()).await,
            StatusCode::FORBIDDEN,
            "account_disabled",
        )
        .await;
        assert_eq!(snapshot_status(&env).await, "disabled");
    }
}

#[tokio::test]
async fn provider_failure_keeps_each_previous_status_and_does_not_issue() {
    for status in ["active", "disabled"] {
        let env = setup().await;
        sqlx::query("UPDATE resource_service_bindings SET snapshot_json = $2 WHERE id = $1")
            .bind(env.binding_id)
            .bind(json!({"status":status}))
            .execute(&env.database)
            .await
            .unwrap();
        *env.stub.mode.lock().unwrap() = Some("unavailable");
        assert_error(
            exchange(&env, Some(&env.token), valid_body()).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
        )
        .await;
        assert_eq!(snapshot_status(&env).await, status);
    }
}

#[tokio::test]
async fn consent_revoked_during_provider_query_prevents_ticket() {
    let env = setup().await;
    env.stub.revoke_consent.store(true, Ordering::SeqCst);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::UNAUTHORIZED,
        "invalid_chenxing_token",
    )
    .await;
}

#[tokio::test]
async fn unlink_during_provider_query_cannot_restore_binding() {
    let env = setup().await;
    env.stub.unlink.store(true, Ordering::SeqCst);
    assert_error(
        exchange(&env, Some(&env.token), valid_body()).await,
        StatusCode::FORBIDDEN,
        "account_not_linked",
    )
    .await;
    let tombstoned: bool = sqlx::query_scalar(
        "SELECT tombstoned_at IS NOT NULL FROM resource_service_bindings WHERE id = $1",
    )
    .bind(env.binding_id)
    .fetch_one(&env.database)
    .await
    .unwrap();
    assert!(tombstoned);
}

#[tokio::test]
async fn expired_provider_access_token_is_refreshed_for_exchange() {
    let env = setup().await;
    sqlx::query("UPDATE resource_service_bindings SET access_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(env.binding_id).execute(&env.database).await.unwrap();
    let response = exchange(&env, Some(&env.token), valid_body()).await;
    let status = response.status();
    let body = http::json_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let generation: i64 =
        sqlx::query_scalar("SELECT generation FROM resource_service_bindings WHERE id = $1")
            .bind(env.binding_id)
            .fetch_one(&env.database)
            .await
            .unwrap();
    assert_eq!(generation, 2);
}

struct OverlappingRefresh {
    inner: Arc<ExchangeProvider>,
    calls: AtomicUsize,
    entered: tokio::sync::Semaphore,
    first_release: tokio::sync::Semaphore,
    second_release: tokio::sync::Semaphore,
}

impl ProviderTransport for OverlappingRefresh {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            if request.url.path().ends_with("/refresh") {
                let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
                self.entered.add_permits(1);
                if first {
                    self.first_release.acquire().await.unwrap().forget();
                    let mut response = self.inner.execute(request).await?;
                    let mut body: Value = serde_json::from_slice(&response.body).unwrap();
                    body["snapshot"]["status"] = json!("disabled");
                    response.body = serde_json::to_vec(&body).unwrap();
                    return Ok(response);
                }
                self.second_release.acquire().await.unwrap().forget();
                return Err(TransportError::Unavailable);
            }
            self.inner.execute(request).await
        })
    }
}

async fn exchange_router(router: Router, token: String) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/auth/chenxing/exchange")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(valid_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn skipped_refresh_snapshot_cannot_authorize_with_old_active_cache() {
    let mut env = setup().await;
    sqlx::query("UPDATE resource_service_bindings SET access_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(env.binding_id).execute(&env.database).await.unwrap();
    let stub = Arc::new(OverlappingRefresh {
        inner: env.stub.clone(),
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Semaphore::new(0),
        first_release: tokio::sync::Semaphore::new(0),
        second_release: tokio::sync::Semaphore::new(0),
    });
    env.state.resource_services = env
        .state
        .resource_services
        .clone()
        .with_transport_override(stub.clone());
    env.router = api::router(env.state.clone());
    let first = tokio::spawn(exchange_router(env.router.clone(), env.token.clone()));
    stub.entered.acquire().await.unwrap().forget();
    let second = tokio::spawn(exchange_router(env.router.clone(), env.token.clone()));
    stub.entered.acquire().await.unwrap().forget();
    stub.first_release.add_permits(1);
    assert_error(
        first.await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "provider_unavailable",
    )
    .await;
    stub.second_release.add_permits(1);
    assert_error(
        second.await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "provider_unavailable",
    )
    .await;
    assert_eq!(snapshot_status(&env).await, "active");
}
