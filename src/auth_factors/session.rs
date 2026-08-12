use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{fmt, time::Duration};

use crate::{
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::Session, store::SessionStoreError},
    state::AppState,
    users::domain::{AuthenticatedUser, UserStatus},
};

#[derive(Serialize)]
pub struct LoginResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginResponse")
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

const SESSION_RESPONSE_MODE_HEADER: &str = "x-chenxing-session-mode";
const SESSION_RESPONSE_TOKEN_MODE: &str = "token";

/// 认证依据在签发完成前被作废时返回的错误码。
///
/// 每个端点用自己已声明的 401 词表，避免修复引入未文档化的错误码：
/// 登录端点声明了 `invalid_credentials`，因子端点声明的是 `invalid_factor`。
/// 两者对客户端的含义一致——本次登录作废，重新走一遍。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleCredentialCode {
    InvalidCredentials,
    InvalidFactor,
}

impl StaleCredentialCode {
    fn response(self) -> Response {
        match self {
            Self::InvalidCredentials => error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            ),
            Self::InvalidFactor => {
                error::unauthorized("invalid_factor", "authentication factor is invalid")
            }
        }
    }
}

/// 签发浏览器会话。
///
/// `authenticated` 必须来自一次真实的第一因子校验（口令）或由该校验派生的
/// login ticket，会话写入会在持锁事务内确认它携带的 `session_epoch` 仍是当前值
/// （Issue #274）。版本漂移只可能由"改密并撤销全部会话"造成，因此按认证失败处理，
/// 不回落成"用当前 epoch 重签"。
pub async fn issue_user_session(
    state: &AppState,
    authenticated: AuthenticatedUser,
    factor: &str,
    headers: &HeaderMap,
    stale_credential: StaleCredentialCode,
) -> Response {
    let user_id = authenticated.id;
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load session user");
            return error::internal();
        }
    }) else {
        return error::unauthorized("invalid_session", "user account is invalid");
    };
    if UserStatus::parse(&profile.status) != Some(UserStatus::Active) {
        return error::unauthorized("user_disabled", "user account is disabled");
    }
    let ttl = Duration::from_secs(state.config.session_ttl_seconds);
    let idle_timeout = Duration::from_secs(state.config.session_idle_timeout_seconds);
    let mut session = match Session::new_at_with_idle_timeout(
        user_id.to_string(),
        ttl,
        idle_timeout,
        state.clock.now(),
    ) {
        Ok(session) => session,
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to create session");
            return error::internal();
        }
    };
    if let Err(session_error) = state
        .sessions
        .save_authenticated(&mut session, ttl, authenticated.session_epoch)
        .await
    {
        match &session_error {
            SessionStoreError::UserDisabled => {
                return error::unauthorized("user_disabled", "user account is disabled");
            }
            // 并发改密已经作废了本次认证依据的口令：按凭据失效处理，
            // 复用调用端点自己已声明的 401 词表，不泄露"发生了改密"。
            SessionStoreError::AuthenticationEpochChanged => {
                return stale_credential.response();
            }
            _ => {}
        }
        tracing::error!(error = %session_error, "failed to persist session");
        return error::internal();
    }
    if state
        .audit
        .record_blocking(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "factor": factor}),
        ))
        .await
        .is_err()
    {
        if let Err(error_value) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %error_value,
                "failed to compensate session after audit persistence failure"
            );
        }
        return error::internal();
    }
    if let Err(factor_error) = state.factors.clear_account_failures(user_id).await {
        if let Err(revoke_error) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %revoke_error,
                "failed to compensate session after account failure cleanup error"
            );
        }
        tracing::error!(
            error = %factor_error,
            "failed to clear account authentication failures after session issuance"
        );
        return error::internal();
    }
    let mut response = (
        StatusCode::OK,
        Json(LoginResponse {
            session_id: should_return_session_token(
                state.config.session_token_response_enabled,
                headers,
            )
            .then(|| session.token.clone()),
            expires_at: session.expires_at,
        }),
    )
        .into_response();
    let cookie_result = cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    )
    .and_then(|()| {
        cookies::append_clear_login_ticket_cookies(
            response.headers_mut(),
            state.config.cookie_secure,
        )
    });
    if let Err(cookie_error) = cookie_result {
        if let Err(revoke_error) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %revoke_error,
                "failed to compensate session after cookie response failure"
            );
        }
        tracing::error!(error = %cookie_error, "failed to build login cookie response");
        return error::internal();
    }
    response
}

fn should_return_session_token(enabled: bool, headers: &HeaderMap) -> bool {
    enabled
        && headers
            .get(SESSION_RESPONSE_MODE_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == SESSION_RESPONSE_TOKEN_MODE)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    use super::{LoginResponse, StaleCredentialCode, should_return_session_token};

    /// Issue #274：认证 epoch 漂移一律映射成 401，且只用调用端点已声明的错误码。
    ///
    /// 两个变体都必须是 401 而不是 5xx：这是一次凭据失效，不是服务端故障。
    /// 断言错误码字面量，是为了守住"修复不新增未文档化错误码"这条约束。
    #[tokio::test]
    async fn stale_credential_codes_map_to_documented_unauthorized_responses() {
        for (code, expected) in [
            (
                StaleCredentialCode::InvalidCredentials,
                "invalid_credentials",
            ),
            (StaleCredentialCode::InvalidFactor, "invalid_factor"),
        ] {
            let response = code.response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{expected}");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("error body");
            let payload: serde_json::Value =
                serde_json::from_slice(&body).expect("JSON error body");
            assert_eq!(payload["code"], expected);
        }
        assert_ne!(
            StaleCredentialCode::InvalidCredentials,
            StaleCredentialCode::InvalidFactor
        );
    }

    #[test]
    fn session_token_response_requires_opt_in_configuration_and_header() {
        let mut headers = HeaderMap::new();
        assert!(!should_return_session_token(false, &headers));
        assert!(!should_return_session_token(true, &headers));

        headers.insert("x-chenxing-session-mode", HeaderValue::from_static("token"));
        assert!(!should_return_session_token(false, &headers));
        assert!(should_return_session_token(true, &headers));
    }

    #[test]
    fn login_response_serializes_expiry_as_rfc3339() {
        let value = serde_json::to_value(LoginResponse {
            session_id: None,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("login response serializes");

        assert_eq!(value["expires_at"], "1970-01-01T00:00:00Z");
    }
}
