use axum::http::HeaderMap;
use thiserror::Error;

use crate::{
    sessions::store::SessionStoreError,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::{
        domain::{UserId, UserStatus},
        service::UserServiceError,
    },
};

#[derive(Debug, Error)]
pub enum SessionLookupError {
    #[error("session store operation failed: {0}")]
    Store(#[from] SessionStoreError),
    #[error("session user lookup failed: {0}")]
    User(#[from] UserServiceError),
}

pub async fn session_for_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Session>, SessionLookupError> {
    let Some(session_token) = session_id_from_headers(
        headers,
        state.config.oauth_session_header_enabled,
        state.config.cookie_secure,
    ) else {
        return Ok(None);
    };
    let Some(session) = state.sessions.find(&session_token).await? else {
        return Ok(None);
    };
    if !session.is_active_at(state.clock.now()) {
        return Ok(None);
    }
    if active_user_id(state, &session.user_id).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(session))
}

pub async fn session_user_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, SessionLookupError> {
    session_for_headers(state, headers)
        .await
        .map(|session| session.map(|session| session.user_id))
}

pub async fn active_user_id(
    state: &AppState,
    user_id: &str,
) -> Result<Option<UserId>, UserServiceError> {
    let Ok(user_id) = user_id.parse::<UserId>() else {
        return Ok(None);
    };
    let Some(profile) = state.users.find_profile(user_id).await? else {
        return Ok(None);
    };
    Ok((UserStatus::parse(&profile.status) == Some(UserStatus::Active)).then_some(user_id))
}

/// 读取 active 用户的当前 `session_epoch`（Issue #409）。
///
/// 与 [`active_user_id`] 的 active 判定共用同一次读取，但返回 epoch 供凭据代际
/// 比对：Refresh Token 签发时 stamp 当前值，兑换时要求一致。任何推进
/// `session_epoch` 的撤销操作（改密、管理端 TOTP 重置、禁用账号）都会让该用户
/// 此前签发的全部 Refresh Token 立即失效——这与会话校验既有的
/// `sessions.session_epoch >= users.session_epoch` 判定对齐。
pub async fn active_user_epoch(
    state: &AppState,
    user_id: &str,
) -> Result<Option<i64>, UserServiceError> {
    let Ok(user_id) = user_id.parse::<UserId>() else {
        return Ok(None);
    };
    state.users.active_session_epoch(user_id).await
}

/// 从请求头部取出会话标识：仓库内唯一的「header 还是 cookie」判定点（Issue #306）。
///
/// 三条规则缺一不可：
/// - Cookie 是生产浏览器的唯一来源，按传输安全性选择 `__Host-` 或本地名。
/// - `X-Chenxing-Session` 只在 `OAUTH_SESSION_HEADER_ENABLED=true` 时被接受，
///   它是开发期兼容通道，不是生产认证方式。
/// - 两者同时出现且不一致时拒绝，而不是任选其一：否则攻击者只要能注入一个头部，
///   就能让服务端忽略浏览器实际持有的 Cookie 会话。
///
/// `sessions::cookies` 不再导出任何「header 优先、无条件回退 cookie」的便捷函数，
/// 因此不存在绕过这三条规则的第二条路径。
fn session_id_from_headers(
    headers: &HeaderMap,
    allow_header: bool,
    secure: bool,
) -> Option<String> {
    let cookie = match cookies::session_cookie_id_for_secure_transport(headers, secure) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let header = cookies::session_header_id(headers);
    if cookie.is_some() && header.is_some() && cookie != header {
        return None;
    }
    cookie.or_else(|| allow_header.then_some(header).flatten())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::session_id_from_headers;

    #[test]
    fn authorization_session_accepts_browser_cookie() {
        let session_id = "random-session-token";
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("__Host-chenxing_session={session_id}"))
                .expect("valid cookie header"),
        );

        assert_eq!(
            session_id_from_headers(&headers, false, true).as_deref(),
            Some(session_id)
        );
    }

    #[test]
    fn authorization_session_header_requires_explicit_compatibility_flag() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("header-session-token"),
        );

        assert_eq!(session_id_from_headers(&headers, false, true), None);
        assert_eq!(
            session_id_from_headers(&headers, true, true).as_deref(),
            Some("header-session-token")
        );
    }

    /// #306：头部被关闭时，同一请求里的 Cookie 会话仍然照常被接受，
    /// 头部的值则完全不参与判定——关闭开关不等于让请求整体失效。
    #[test]
    fn a_disabled_header_is_ignored_but_the_cookie_still_authenticates() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("__Host-chenxing_session=cookie-session-token"),
        );
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("cookie-session-token"),
        );

        assert_eq!(
            session_id_from_headers(&headers, false, true).as_deref(),
            Some("cookie-session-token")
        );
    }

    /// #306：头部被关闭也不放松冲突检查。允许「关闭时忽略冲突」等于把开关变成
    /// 一个能被头部注入绕过的软约束。
    #[test]
    fn mismatched_cookie_and_header_are_rejected_even_when_the_header_is_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("__Host-chenxing_session=cookie-session-token"),
        );
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("header-session-token"),
        );

        assert_eq!(session_id_from_headers(&headers, false, true), None);
    }

    #[test]
    fn mismatched_cookie_and_header_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("__Host-chenxing_session=cookie-session-token"),
        );
        headers.insert(
            "x-chenxing-session",
            HeaderValue::from_static("header-session-token"),
        );

        assert_eq!(session_id_from_headers(&headers, true, true), None);
    }
}
