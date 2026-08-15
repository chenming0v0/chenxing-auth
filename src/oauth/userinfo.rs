use serde::{Deserialize, Serialize};
use std::fmt;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, RawForm, State, rejection::RawFormRejection},
    http::{HeaderMap, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::{
    api::extract::RequestIssuer,
    error,
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        response::with_no_store_headers,
        token::decode_userinfo_token,
        token_security::enforce_source_qps_with_policy,
    },
    state::AppState,
    users::domain::UserStatus,
};

use super::form;

#[derive(Debug, Clone, Serialize)]
pub struct UserInfoClaims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct UserInfoRequest {
    pub access_token: Option<String>,
}

impl fmt::Debug for UserInfoRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserInfoRequest")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl UserInfoClaims {
    pub fn from_profile(
        subject: String,
        email: String,
        name: Option<String>,
        scopes: &[String],
    ) -> Self {
        let has_email = scopes.iter().any(|scope| scope == "email");
        let has_profile = scopes.iter().any(|scope| scope == "profile");
        Self {
            sub: subject,
            email: has_email.then_some(email),
            name: has_profile.then_some(name).flatten(),
        }
    }
}

pub async fn userinfo(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip.as_deref()).await {
        return with_no_store_headers(response);
    }

    with_no_store_headers(userinfo_inner(state, issuer, headers, None).await)
}

pub async fn userinfo_post(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<RawForm, RawFormRejection>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip.as_deref()).await {
        return with_no_store_headers(response);
    }

    let RawForm(body) = match form {
        Ok(form) => form,
        Err(_) => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    let request: UserInfoRequest = match form::deserialize(&body) {
        Some(request) => request,
        None => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    with_no_store_headers(
        userinfo_inner(state, issuer, headers, request.access_token.as_deref()).await,
    )
}

async fn userinfo_inner(
    state: AppState,
    issuer: RequestIssuer,
    headers: HeaderMap,
    form_access_token: Option<&str>,
) -> Response {
    let token = match access_token(&headers, form_access_token) {
        Ok(Some(token)) => token,
        Ok(None) => return error::oauth_invalid_bearer("Bearer access token is required"),
        Err(()) => {
            return error::oauth_bad_request(
                "invalid_request",
                "access token must not be sent in both header and form",
            );
        }
    };
    let claims = match decode_userinfo_token(&state.keys, issuer.issuer().as_str(), &token) {
        Ok(claims) => claims,
        Err(token_error) => {
            tracing::info!(error = %token_error, "UserInfo access token rejected");
            return error::oauth_invalid_bearer("access token is invalid");
        }
    };
    match state.revocations.is_revoked(&token).await {
        Ok(true) => return error::oauth_invalid_bearer("access token is invalid"),
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check access token revocation");
            return error::oauth_temporarily_unavailable();
        }
    }
    let Ok(user_id) = claims.sub.parse::<crate::users::domain::UserId>() else {
        return error::oauth_invalid_bearer("access token is invalid");
    };
    // Access tokens are self-contained, but client status is authoritative in PostgreSQL.
    // Disabled clients lose UserInfo access immediately instead of waiting for JWT expiry.
    match state.clients.find_registered(&claims.aud).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::oauth_invalid_bearer("access token is invalid"),
        Err(service_error) => {
            tracing::error!(error = %service_error, "failed to load OAuth client for UserInfo");
            return error::oauth_temporarily_unavailable();
        }
    }
    let presented = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    // Access Token 的默认寿命是 3600 秒，期间用户可能撤销授权、管理员可能禁用
    // Client 或缩减其注册 scope。此前这里只查 consent：禁用客户端后 AT 仍能
    // 拉用户信息（Issue #420），缩减 scope 后 claim 仍按旧集合返回（#421）。
    //
    // 返回的是收窄后的集合，下面按它决定放出哪些 claim——只拒绝整个请求并不
    // 等于收窄权限。
    let scopes = match effective_grant_scopes(&state, &claims.sub, &claims.aud, &presented).await {
        Ok(grant) => grant.scopes,
        Err(GrantGateError::Denied(_)) => {
            return error::oauth_invalid_bearer("access token is invalid");
        }
        Err(GrantGateError::Unavailable(_)) => return error::oauth_temporarily_unavailable(),
    };
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load UserInfo profile");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return error::oauth_invalid_bearer("access token is invalid");
    };
    if UserStatus::parse(&profile.status) != Some(UserStatus::Active) {
        return error::oauth_invalid_bearer("access token is invalid");
    }

    let userinfo = UserInfoClaims::from_profile(
        profile.id.to_string(),
        profile.email,
        profile.display_name,
        &scopes,
    );
    (axum::http::StatusCode::OK, Json(userinfo)).into_response()
}

fn access_token(
    headers: &HeaderMap,
    form_access_token: Option<&str>,
) -> Result<Option<String>, ()> {
    let header_access_token = bearer_token(headers);
    if header_access_token.is_some() && form_access_token.is_some() {
        return Err(());
    }
    Ok(header_access_token
        .map(str::to_owned)
        .or_else(|| form_access_token.map(str::to_owned)))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, credentials) =
                value.split_once(|character: char| character.is_ascii_whitespace())?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then_some(credentials.trim_start())
        })
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_token_accepts_case_insensitive_bearer_scheme() {
        for authorization in ["Bearer token", "bearer token", "BEARER token"] {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_static(authorization));

            assert_eq!(bearer_token(&headers), Some("token"), "{authorization}");
        }
    }

    #[test]
    fn bearer_token_rejects_missing_or_empty_credentials() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);

        for authorization in ["Bearer", "Bearer ", "Bearer   ", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_static(authorization));

            assert_eq!(bearer_token(&headers), None, "{authorization:?}");
        }
    }

    #[test]
    fn bearer_token_rejects_other_authentication_schemes() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic token"));

        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn access_token_rejects_header_and_form_conflict() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer header"));

        assert_eq!(access_token(&headers, Some("form")), Err(()));
    }

    #[test]
    fn access_token_accepts_either_header_or_form() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer header"));

        assert_eq!(
            access_token(&headers, None).expect("header token"),
            Some("header".to_owned())
        );
        assert_eq!(
            access_token(&HeaderMap::new(), Some("form")).expect("form token"),
            Some("form".to_owned())
        );
    }
}
