use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};

use crate::{
    error,
    oauth::{authorization::AuthorizationRequest, consent::PendingAuthorization},
    state::AppState,
};

pub async fn pending_request_exists(state: &AppState, request_id: &str) -> bool {
    state
        .authorization_requests
        .find(request_id)
        .await
        .ok()
        .flatten()
        .is_some()
}

pub async fn load_pending(state: &AppState, request_id: &str) -> Option<PendingAuthorization> {
    state
        .authorization_requests
        .find(request_id)
        .await
        .ok()
        .flatten()
}

pub async fn validate_pending(
    state: &AppState,
    pending: &PendingAuthorization,
) -> Result<(), Response> {
    let Some(client) = state
        .clients
        .find_registered(&pending.client_id)
        .await
        .map_err(|database_error| {
            tracing::error!(error = %database_error, "failed to validate pending client");
            error::internal()
        })?
    else {
        return Err(html_error(
            StatusCode::BAD_REQUEST,
            "接入应用无效，授权请求无法继续。",
        ));
    };
    crate::oauth::authorization::validate_authorization_request(
        &client,
        AuthorizationRequest {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            response_type: "code".to_owned(),
            scope: pending.scope.clone(),
            state: Some(pending.state.clone()),
            nonce: pending.nonce.clone(),
            code_challenge: Some(pending.code_challenge.clone()),
            code_challenge_method: Some(pending.code_challenge_method.clone()),
        },
    )
    .map(|_| ())
    .map_err(|_| {
        html_error(
            StatusCode::BAD_REQUEST,
            "授权请求已失效，请从接入平台重新开始。",
        )
    })
}

pub fn redirect_with_error(redirect_uri: &str, state_value: &str) -> Response {
    let Ok(mut redirect) = url::Url::parse(redirect_uri) else {
        return error::internal();
    };
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", state_value);
    Redirect::to(redirect.as_str()).into_response()
}

pub fn html_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(crate::web::page(
            "辰星认证中枢",
            &format!(
                "<main><h1>请求无法继续</h1><p>{}</p></main>",
                crate::web::escape_html(message)
            ),
        )),
    )
        .into_response()
}
