use crate::{
    audit::AuditEvent,
    error,
    oauth::providers::{service::ExternalOAuthError, state_store::ExternalLoginState},
    sessions::{cookies, domain::Session},
    state::AppState,
    web::helpers::{html_error, pending_request_exists},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ExternalLoginQuery {
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn start_external_login(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<ExternalLoginQuery>,
) -> Response {
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        Ok(_) => return external_error(&state, &slug, "oauth_provider_not_found").await,
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to load external OAuth provider");
            return external_error(&state, &slug, "oauth_login_failed").await;
        }
    };
    if let Some(request_id) = query.request_id.as_deref()
        && !pending_request_exists(&state, request_id).await
    {
        return html_error(
            StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始登录。",
        );
    }
    let state_value = random_state();
    if let Err(store_error) = state
        .external_login_states
        .save(&ExternalLoginState {
            state: state_value.clone(),
            provider_slug: slug.clone(),
            request_id: query.request_id.clone().filter(|value| !value.is_empty()),
        })
        .await
    {
        tracing::error!(error = %store_error, "failed to store external OAuth state");
        return error::internal();
    }
    let callback = format!("{}/auth/external/{slug}/callback", state.config.issuer_url);
    let authorization_url = match state.external_oauth.authorization_url(
        &provider,
        &callback,
        &state_value,
    ) {
        Ok(url) => url,
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to build external OAuth URL");
            return external_error(&state, &slug, "oauth_login_failed").await;
        }
    };
    let mut response = Redirect::to(&authorization_url).into_response();
    cookies::append_external_state_cookie(
        response.headers_mut(),
        &state_value,
        600,
        state.config.cookie_secure,
    );
    response
}

pub async fn external_callback(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(query): Query<ExternalCallbackQuery>,
) -> Response {
    let cookie_state = cookies::external_state(&headers);
    let Some(returned_state) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return external_error(&state, &slug, "oauth_login_failed").await;
    };
    if cookie_state.as_deref() != Some(returned_state) {
        return external_error(&state, &slug, "oauth_login_failed").await;
    }
    let stored_state = match state.external_login_states.take(returned_state).await {
        Ok(Some(value)) if value.provider_slug == slug => value,
        Ok(_) => return external_error(&state, &slug, "oauth_login_failed").await,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to consume external OAuth state");
            return external_error(&state, &slug, "oauth_login_failed").await;
        }
    };
    if query.error.is_some() {
        return external_error_with_request(
            &state,
            &slug,
            stored_state.request_id.as_deref(),
            "oauth_login_failed",
        )
        .await;
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return external_error_with_request(
            &state,
            &slug,
            stored_state.request_id.as_deref(),
            "oauth_login_failed",
        )
        .await;
    };
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        _ => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_provider_not_found",
            )
            .await;
        }
    };
    let callback = format!("{}/auth/external/{slug}/callback", state.config.issuer_url);
    let token = match state
        .external_oauth
        .exchange_code(&provider, &callback, code)
        .await
    {
        Ok(token) => token,
        Err(error_value) => {
            tracing::info!(error = %error_value, provider = %slug, "external OAuth token exchange failed");
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_login_failed",
            )
            .await;
        }
    };
    let external_user = match state.external_oauth.userinfo(&provider, &token).await {
        Ok(user) => user,
        Err(error_value) => {
            tracing::info!(error = %error_value, provider = %slug, "external OAuth userinfo failed");
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_login_failed",
            )
            .await;
        }
    };
    let user_id = match state
        .external_oauth
        .resolve_user(&provider, &external_user)
        .await
    {
        Ok(user_id) => user_id,
        Err(ExternalOAuthError::EmailAlreadyRegistered) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_account_link_required",
            )
            .await;
        }
        Err(ExternalOAuthError::UserDisabled) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_login_failed",
            )
            .await;
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to resolve external OAuth identity");
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                "oauth_login_failed",
            )
            .await;
        }
    };
    let ttl = std::time::Duration::from_secs(state.config.session_ttl_seconds);
    let mut session = match Session::new(user_id.to_string(), ttl) {
        Ok(session) => session,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create external OAuth session");
            return error::internal();
        }
    };
    if let Err(error_value) = state.sessions.save(&mut session, ttl).await {
        tracing::error!(error = %error_value, "failed to save external OAuth session");
        return error::internal();
    }
    state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "channel": "external_oauth", "provider": slug}),
        ))
        .await;
    let mut response = if let Some(request_id) = stored_state.request_id {
        Redirect::to(&format!("/oauth/authorize/consent?request_id={request_id}")).into_response()
    } else {
        Redirect::to("/auth/login?external=success").into_response()
    };
    cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    cookies::append_clear_external_state_cookie(response.headers_mut(), state.config.cookie_secure);
    response
}

async fn external_error(state: &AppState, slug: &str, code: &str) -> Response {
    external_error_with_request(state, slug, None, code).await
}

async fn external_error_with_request(
    state: &AppState,
    slug: &str,
    request_id: Option<&str>,
    code: &str,
) -> Response {
    tracing::info!(provider = %slug, error_code = %code, "external OAuth login failed");
    let location = match request_id.filter(|value| !value.is_empty()) {
        Some(request_id) => format!("/auth/login?request_id={request_id}&external_error={code}"),
        None => format!("/auth/login?external_error={code}"),
    };
    let mut response = Redirect::to(&location).into_response();
    cookies::append_clear_external_state_cookie(response.headers_mut(), state.config.cookie_secure);
    response
}

fn random_state() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
