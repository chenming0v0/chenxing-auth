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
    let mut response = external_failure_redirect(request_id, code);
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

/// 外部登录已经解析出用户并建好 Session，但把 Session 绑定到 pending 授权请求失败。
///
/// 语义是 fail-closed：绑定失败等于本次登录失败，因此先撤销刚创建的 Session，再清掉
/// 浏览器里可能存在的会话与 CSRF Cookie，响应绝不携带可用的登录凭据。否则一次绑定
/// 失败会留下"登录成功"的副作用——Session 仍在存储中有效、Cookie 已下发——调用方
/// 就能绕过绑定校验拿到可用会话（#266）。
///
/// 审计主体用已解析出的用户，而不是 `anonymous`：这条失败确实发生在某个已知用户的
/// 登录过程中，记成匿名会让失败无法归因。Session 令牌本身不进审计。
pub(super) async fn external_binding_failure(
    state: &AppState,
    slug: &str,
    request_id: &str,
    state_value: &str,
    code: &str,
    session: &Session,
) -> Response {
    let session_revoked = revoke_session_best_effort(state, session).await;
    state
        .audit
        .record_best_effort(AuditEvent::security_failure(
            "login_failure".to_owned(),
            "user".to_owned(),
            Some(session.user_id.clone()),
            "external_oauth".to_owned(),
            Some(slug.to_owned()),
            code,
        ))
        .await;
    tracing::info!(
        provider = %slug,
        error_code = %code,
        session_revoked,
        "external OAuth login failed while binding the pending authorization request"
    );
    match try_binding_failure_response(state, slug, request_id, state_value, code) {
        Ok(response) => response,
        Err(cookie_error) => cookie_error_response(cookie_error),
    }
}

fn try_binding_failure_response(
    state: &AppState,
    slug: &str,
    request_id: &str,
    state_value: &str,
    code: &str,
) -> Result<Response, cookies::CookieError> {
    let mut response = external_failure_redirect(Some(request_id), code);
    // 撤销后浏览器不应再留着任何指向该会话的 Cookie；两个名字都由 helper 按
    // `cookie_secure` 选择，和下发时保持一致。
    cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)?;
    append_external_state_clear(
        &mut response,
        state_value,
        &external_callback_path(slug),
        state.config.cookie_secure,
    )?;
    Ok(response)
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

fn external_failure_redirect(request_id: Option<&str>, code: &str) -> Response {
    let location = match request_id.filter(|value| !value.is_empty()) {
        Some(request_id) => format!("/login?request_id={request_id}&external_error={code}"),
        None => format!("/login?external_error={code}"),
    };
    Redirect::to(&location).into_response()
}

fn cookie_error_response(cookie_error: cookies::CookieError) -> Response {
    tracing::error!(error = %cookie_error, "failed to build external OAuth cookie response");
    error::internal()
}

/// 撤销失败不改变响应：Cookie 已经被清掉，且响应不含有效登录凭据。返回撤销是否成功，
/// 供日志区分"会话已确定失效"和"存储撤销失败、需靠 TTL 兜底"。
async fn revoke_session_best_effort(state: &AppState, session: &Session) -> bool {
    match state.sessions.revoke(&session.token).await {
        Ok(()) => true,
        Err(revoke_error) => {
            tracing::warn!(
                error = %revoke_error,
                "failed to revoke external OAuth session after login failure"
            );
            false
        }
    }
}

pub(super) fn external_callback_path(slug: &str) -> String {
    format!("/auth/external/{slug}/callback")
}
