use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::{
    clients::{domain::ClientRegistrationInput, service::ClientServiceError},
    oauth::{
        handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
        quota::QuotaConsumeResult,
        store::AuthorizationCodeStore,
    },
    plans::domain::{AuthQuotaLimits, MAX_DAILY_AUTH_LIMIT, MAX_MONTHLY_AUTH_LIMIT, MAX_QPS},
};
use serde_json::Value;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Barrier;
use tower::ServiceExt;
use uuid::Uuid;

use crate::plans_support as support;

use support::{
    ADMIN_TOKEN, DEFAULT_PLAN_CODE, REDIRECT_URI, active_default_plan_count, archive_plan,
    assign_plan, authorization_code_from_redirect, bootstrap_owner, clear_all_plans,
    code_challenge_for, create_admin_client, create_owned_client, create_plan,
    exchange_authorization_code, get_entitlements, json, list_owned_clients, list_plans,
    plan_limits, plan_status_and_default, post_owned_client, register_user, restore_plan,
    submit_plan, test_state_from_template, update_plan, user_session, validated_request,
    validated_request_with_challenge,
};

fn test_issuer(
    state: &chenxing_auth::state::AppState,
) -> std::sync::Arc<chenxing_auth::settings::IssuerSnapshot> {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
}

/// #508：无会话绑定的授权码在 Token 端点 fail-closed，直存授权码走兑换路径的
/// 测试必须先把码绑定到一条已持久化的浏览器会话上。
async fn bound_session_token(state: &chenxing_auth::state::AppState, user_id: i64) -> String {
    use chenxing_auth::sessions::domain::Session;
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session.token
}

mod authorization_quota;
mod default_plan;
mod entitlements;
mod plan_admin;
mod plan_boundaries;
mod plan_quota;
mod qps_limit;
