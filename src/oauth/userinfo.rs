use serde::Serialize;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
    response::Response,
};

use crate::{error, oauth::token::decode_userinfo_token, state::AppState};

#[derive(Debug, Clone, Serialize)]
pub struct UserInfoClaims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return error::unauthorized("invalid_token", "Bearer access token is required");
    };
    let claims = match decode_userinfo_token(&state.keys, &state.config.issuer_url, token) {
        Ok(claims) => claims,
        Err(token_error) => {
            tracing::info!(error = %token_error, "UserInfo access token rejected");
            return error::unauthorized("invalid_token", "access token is invalid");
        }
    };
    match state.revocations.is_revoked(token).await {
        Ok(true) => return error::unauthorized("invalid_token", "access token is revoked"),
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check access token revocation");
            return error::internal();
        }
    }
    let Ok(user_id) = claims.sub.parse::<crate::users::domain::UserId>() else {
        return error::unauthorized("invalid_token", "access token subject is invalid");
    };
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load UserInfo profile");
            return error::internal();
        }
    }) else {
        return error::unauthorized("invalid_token", "access token subject is unknown");
    };
    if profile.status != "active" {
        return error::unauthorized("invalid_token", "user account is not active");
    }

    let scopes = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let userinfo = UserInfoClaims::from_profile(
        profile.id.to_string(),
        profile.email,
        profile.display_name,
        &scopes,
    );
    (axum::http::StatusCode::OK, Json(userinfo)).into_response()
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

use axum::response::IntoResponse;

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
}
