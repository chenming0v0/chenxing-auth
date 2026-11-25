use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use chenxing_auth::{
    resource_services::{
        ProviderHttpRequest, ProviderHttpResponse, ProviderTransport, TransportError,
        TransportFuture,
    },
    sqlx,
};
use serde_json::{Value, json};

pub(crate) struct ExchangeProvider {
    database: sqlx::PgPool,
    pub mode: Mutex<Option<&'static str>>,
    pub calls: AtomicUsize,
    pub revoke_consent: AtomicBool,
    pub unlink: AtomicBool,
}

impl ExchangeProvider {
    pub fn new(database: sqlx::PgPool) -> Self {
        Self {
            database,
            mode: Mutex::new(None),
            calls: AtomicUsize::new(0),
            revoke_consent: AtomicBool::new(false),
            unlink: AtomicBool::new(false),
        }
    }
}

impl ProviderTransport for ExchangeProvider {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mode = *self.mode.lock().unwrap();
            if mode == Some("unavailable") {
                return Err(TransportError::Unavailable);
            }
            if mode == Some("403") {
                return Ok(ProviderHttpResponse {
                    status: 403,
                    retry_after_seconds: None,
                    body: br#"{"error":{"code":"account_disabled","retryable":false}}"#.to_vec(),
                });
            }
            if self.revoke_consent.load(Ordering::SeqCst) {
                sqlx::query("UPDATE user_consents SET revoked_at = NOW(), state_version = state_version + 1")
                    .execute(&self.database).await.unwrap();
            }
            let (uid, cached, binding_id): (String, Value, uuid::Uuid) = sqlx::query_as(
                "SELECT uid, snapshot_json, id FROM resource_service_bindings ORDER BY created_at LIMIT 1",
            ).fetch_one(&self.database).await.unwrap();
            if self.unlink.load(Ordering::SeqCst) {
                sqlx::query("UPDATE resource_service_bindings SET tombstoned_at = NOW(), generation = generation + 1 WHERE id = $1")
                    .bind(binding_id).execute(&self.database).await.unwrap();
            }
            let status = mode.unwrap_or_else(|| cached["status"].as_str().unwrap_or("unknown"));
            let mut snapshot: Value = serde_json::from_str(include_str!(
                "../../../docs/account-provider-v1/fixtures/cltermux-login-snapshot.json"
            ))
            .unwrap();
            snapshot["issuer"] = json!(format!("https://{}", request.url.host_str().unwrap()));
            snapshot["uid"] = json!(uid);
            snapshot["status"] = json!(status);
            snapshot["fields"] = json!([]);
            let mut response = snapshot.clone();
            if request.url.path().ends_with("/refresh") {
                response = serde_json::from_str(include_str!(
                    "../../../docs/account-provider-v1/fixtures/refresh-response.json"
                ))
                .unwrap();
                let request_body: Value = serde_json::from_slice(&request.body).unwrap();
                response["client_binding_id"] = request_body["client_binding_id"].clone();
                response["issuer"] = snapshot["issuer"].clone();
                response["uid"] = snapshot["uid"].clone();
                response["snapshot"] = snapshot;
            }
            Ok(ProviderHttpResponse {
                status: 200,
                retry_after_seconds: None,
                body: serde_json::to_vec(&response).unwrap(),
            })
        })
    }
}
