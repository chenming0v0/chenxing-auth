use crate::{
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
};
use axum::response::{IntoResponse, Redirect, Response};

pub(super) async fn external_error(state: &AppState, slug: &str, code: &str) -> Response {
    external_error_with_request(state, slug, None, None, code).await
}

pub(super) async fn external_error_with_state(
    state: &AppState,
    slug: &str,
    state_value: &str,
    code: &str,
) -> Response {
    external_error_with_request(state, slug, None, Some(state_value), code).await
}

pub(super) async fn external_error_with_request(
    state: &AppState,
    slug: &str,
    request_id: Option<&str>,
    state_value: Option<&str>,
    code: &str,
) -> Response {
    match try_external_error_with_request(state, slug, request_id, state_value, code).await {
        Ok(response) => response,
        Err(cookie_error) => cookie_error_response(cookie_error),
    }
}

async fn try_external_error_with_request(
    state: &AppState,
    slug: &str,
    request_id: Option<&str>,
    state_value: Option<&str>,
    code: &str,
) -> Result<Response, cookies::CookieError> {
    state
        .audit
        .record_best_effort(AuditEvent::security_failure(
            "login_failure".to_owned(),
            "anonymous".to_owned(),
            None,
            "external_oauth".to_owned(),
            Some(slug.to_owned()),
            code,
        ))
        .await;
    tracing::info!(provider = %slug, error_code = %code, "external OAuth login failed");
    let location = match request_id.filter(|value| !value.is_empty()) {
        Some(request_id) => format!("/login?request_id={request_id}&external_error={code}"),
        None => format!("/login?external_error={code}"),
    };
    let mut response = Redirect::to(&location).into_response();
    if let Some(state_value) = state_value {
        append_external_state_clear(
            &mut response,
            state_value,
            &external_callback_path(slug),
            state.config.cookie_secure,
        )?;
    }
    Ok(response)
}

pub(super) async fn external_error_with_session(
    state: &AppState,
    slug: &str,
    request_id: &str,
    state_value: &str,
    code: &str,
    session: &Session,
) -> Response {
    let mut response = match try_external_error_with_request(
        state,
        slug,
        Some(request_id),
        Some(state_value),
        code,
    )
    .await
    {
        Ok(response) => response,
        Err(cookie_error) => {
            let response = cookie_error_response(cookie_error);
            revoke_session_best_effort(state, session).await;
            return response;
        }
    };
    if let Err(cookie_error) = cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    ) {
        let response = cookie_error_response(cookie_error);
        revoke_session_best_effort(state, session).await;
        return response;
    }
    response
}

pub(super) fn append_external_state_clear(
    response: &mut Response,
    state_value: &str,
    callback_path: &str,
    secure: bool,
) -> Result<(), cookies::CookieError> {
    cookies::append_clear_external_state_cookie(
        response.headers_mut(),
        state_value,
        secure,
        callback_path,
    )
}

fn cookie_error_response(cookie_error: cookies::CookieError) -> Response {
    tracing::error!(error = %cookie_error, "failed to build external OAuth cookie response");
    error::internal()
}

async fn revoke_session_best_effort(state: &AppState, session: &Session) {
    if let Err(revoke_error) = state.sessions.revoke(&session.token).await {
        tracing::warn!(
            error = %revoke_error,
            "failed to compensate external OAuth session after cookie response failure"
        );
    }
}

pub(super) fn external_callback_path(slug: &str) -> String {
    format!("/auth/external/{slug}/callback")
}
