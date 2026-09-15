use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::CltermuxConfig, sqlx};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::oauth_flow;

const OUTBOUND: &str = "registry-outbound-0123456789abcdef0123456789";
const INBOUND: &str = "registry-inbound-abcdef0123456789abcdef0123";

fn legacy() -> CltermuxConfig {
    CltermuxConfig {
        base_url: "https://cltermux.example.com/".parse().expect("URL"),
        outbound_token: OUTBOUND.to_owned(),
        inbound_token_digest: Sha256::digest(INBOUND.as_bytes()).to_vec(),
        allowed_client_ids: vec!["registry-client".to_owned()],
    }
}

#[tokio::test]
async fn legacy_import_is_idempotent_and_preserves_explicit_empty_registry() {
    let (state, database, _keys) = oauth_flow::test_state("provider_registry_import").await;
    // Cover both the absent-row INSERT and the already-migrated conflict path.
    sqlx::query("DELETE FROM app_settings WHERE setting_key = 'account_providers'")
        .execute(&database)
        .await
        .expect("remove migration seed");
    state
        .settings
        .import_legacy_account_provider(&legacy())
        .await
        .expect("import");
    let mut changed = legacy();
    changed.outbound_token = "different-outbound-0123456789abcdef01234567".to_owned();
    state
        .settings
        .import_legacy_account_provider(&changed)
        .await
        .expect("repeat import");
    let provider = state
        .settings
        .account_provider("cltermux")
        .await
        .expect("lookup")
        .expect("provider");
    assert_eq!(provider.config.outbound_token, OUTBOUND);
    assert_eq!(provider.version, 1);
    sqlx::query(
        "UPDATE app_settings SET setting_value = '[]' WHERE setting_key = 'account_providers'",
    )
    .execute(&database)
    .await
    .expect("explicit empty registry");
    state
        .settings
        .import_legacy_account_provider(&legacy())
        .await
        .expect("preserve empty");
    assert!(
        state
            .settings
            .account_providers()
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
async fn admin_save_creates_updates_and_rejects_stale_provider_versions() {
    let (state, database, _keys) = oauth_flow::test_state("provider_registry_save").await;
    let router = api::router(state.clone());
    let mut input = json!({
        "slug": "cltermux", "name": "CLtermux", "adapter": "cltermux",
        "base_url": "https://cltermux.example.com/",
        "allowed_client_ids": ["registry-client"], "enabled": true,
        "expected_version": 0, "outbound_token": OUTBOUND, "inbound_token": INBOUND
    });
    for (version, status) in [
        (0, StatusCode::CREATED),
        (1, StatusCode::OK),
        (1, StatusCode::CONFLICT),
    ] {
        input["expected_version"] = json!(version);
        if version > 0 {
            input
                .as_object_mut()
                .expect("object")
                .remove("outbound_token");
            input
                .as_object_mut()
                .expect("object")
                .remove("inbound_token");
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/account-providers/cltermux")
                    .header("authorization", "Bearer flow-admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), status);
        let body = oauth_flow::json_body(response).await;
        assert!(!body.to_string().contains(OUTBOUND));
        assert!(!body.to_string().contains(INBOUND));
        if status.is_success() {
            assert_eq!(body["version"], version + 1);
            assert_eq!(body["outbound_token_configured"], true);
        }
    }
    let stored: String = sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'account_providers'",
    )
    .fetch_one(&database)
    .await
    .expect("persisted registry");
    assert!(!stored.contains(OUTBOUND));
    assert!(!stored.contains(INBOUND));
    let rows: Value = serde_json::from_str(&stored).expect("stored JSON");
    assert_eq!(rows[0]["version"], 2);
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'account_provider_save'",
    )
    .fetch_one(&database)
    .await
    .expect("audit count");
    assert_eq!(events, 2);
    assert_eq!(
        state
            .settings
            .account_provider("cltermux")
            .await
            .expect("lookup")
            .expect("provider")
            .config
            .outbound_token,
        OUTBOUND
    );
}
