use axum::{
    Form,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::helpers::{html_error, load_pending, redirect_with_error, validate_pending};
use crate::{
    error,
    oauth::{
        consent::{ConsentDecision, ConsentForm, parse_decision},
        handlers::{issue_authorization_code, validated_pending_request},
        session::session_for_headers,
    },
    sessions::cookies,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub request_id: String,
}

pub async fn consent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let Some(session) = session_for_headers(&state, &headers).await else {
        return Redirect::to(&format!("/auth/login?request_id={}", query.request_id))
            .into_response();
    };
    let Some(pending) = load_pending(&state, &query.request_id).await else {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始。",
        );
    };
    if let Err(response) = validate_pending(&state, &pending).await {
        return response;
    }
    if pending.session_id != Some(session.id) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    let client_name = match state.clients.find_registered(&pending.client_id).await {
        Ok(Some(client)) => client.client_name,
        Ok(None) => {
            return html_error(
                axum::http::StatusCode::BAD_REQUEST,
                "接入应用无效，授权请求无法继续。",
            );
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load consent client");
            return error::internal();
        }
    };
    let scopes = pending
        .scope
        .split_whitespace()
        .map(crate::web::escape_html)
        .collect::<Vec<_>>()
        .join("、");
    let body = format!(
        "<main><h1>授权确认</h1><p>应用 <strong>{}</strong> 请求访问以下信息：{}</p><form method=\"post\" action=\"/oauth/authorize/consent\"><input type=\"hidden\" name=\"request_id\" value=\"{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"decision\" value=\"approve\" type=\"submit\">同意并继续</button><button name=\"decision\" value=\"deny\" type=\"submit\">拒绝</button></form></main>",
        crate::web::escape_html(&client_name),
        scopes,
        crate::web::escape_html(&pending.request_id),
        crate::web::escape_html(&session.csrf_token)
    );
    Html(crate::web::page("授权确认", &body)).into_response()
}

pub async fn consent_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(session) = session_for_headers(&state, &headers).await else {
        return error::unauthorized("login_required", "an authenticated session is required");
    };
    let Some(csrf_cookie) = cookies::csrf_cookie(&headers) else {
        return error::bad_request("csrf_required", "CSRF token is required");
    };
    if csrf_cookie != form.csrf_token || !session.validates_csrf(&form.csrf_token) {
        return error::bad_request("csrf_invalid", "CSRF token is invalid");
    }
    let Some(decision) = parse_decision(&form.decision) else {
        return error::bad_request("invalid_decision", "authorization decision is invalid");
    };
    let Some(pending) = load_pending(&state, &form.request_id).await else {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始。",
        );
    };
    if let Err(response) = validate_pending(&state, &pending).await {
        return response;
    }
    if pending.session_id != Some(session.id) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    let Some(pending_request) = state
        .authorization_requests
        .take(&form.request_id)
        .await
        .ok()
        .flatten()
    else {
        return html_error(
            axum::http::StatusCode::BAD_REQUEST,
            "授权请求已被处理或已失效。",
        );
    };
    let user_id = match uuid::Uuid::parse_str(&session.user_id) {
        Ok(user_id) => user_id,
        Err(_) => return error::unauthorized("invalid_session", "session user is invalid"),
    };
    if matches!(decision, ConsentDecision::Deny) {
        return redirect_with_error(&pending_request.redirect_uri, &pending_request.state);
    }
    let scopes = pending_request
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Err(database_error) = state
        .consents
        .save(user_id, &pending_request.client_id, &scopes)
        .await
    {
        tracing::error!(error = %database_error, "failed to save user consent");
        return error::internal();
    }
    issue_authorization_code(
        &state,
        session.user_id,
        validated_pending_request(pending_request),
    )
    .await
}
