use super::pkce::validate_s256_challenge;
use crate::clients::domain::{DEFAULT_ALLOWED_SCOPES, canonicalize_redirect_uri};
use crate::users::domain::UserId;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use url::{Host, Url};

/// Maximum number of Unicode scalar values accepted for the OAuth `state` value.
pub const MAX_STATE_LENGTH: usize = 512;
/// Maximum number of Unicode scalar values accepted for the OIDC `nonce` value.
pub const MAX_NONCE_LENGTH: usize = 512;

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("response_type", &self.response_type)
            .field("scope", &self.scope)
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field(
                "code_challenge",
                &self.code_challenge.as_ref().map(|_| "<redacted>"),
            )
            .field("code_challenge_method", &self.code_challenge_method)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub owner_user_id: Option<UserId>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub owner_user_id: Option<UserId>,
    /// 发起该授权请求的浏览器会话令牌 SHA-256 摘要，用于把签发出的授权码绑定到会话。
    ///
    /// 协议校验阶段拿不到会话（`/oauth/authorize` 的查询参数里不该、也不能带
    /// 会话凭据，否则会话令牌会进 Referer 和访问日志），因此
    /// `validate_authorization_request` 一律填 `None`，由持有会话的调用方
    /// （`handlers::authorize_request` / 授权确认页）在校验之后回填。
    pub session_token_hash: Option<String>,
}

impl fmt::Debug for ValidatedAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedAuthorizationRequest")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("state", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("code_challenge", &"<redacted>")
            .field("owner_user_id", &self.owner_user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationRequestError {
    #[error("client id is invalid")]
    InvalidClient,
    #[error("redirect URI is not registered")]
    RedirectUriNotAllowed,
    #[error("response type must be code")]
    UnsupportedResponseType,
    #[error("requested scope is not allowed")]
    ScopeNotAllowed,
    #[error("state is required")]
    MissingState,
    #[error("state is too long")]
    StateTooLong,
    #[error("nonce is too long")]
    NonceTooLong,
    #[error("PKCE S256 is required")]
    PkceRequired,
    #[error("PKCE S256 challenge is invalid")]
    InvalidCodeChallenge,
}

pub fn validate_authorization_request(
    client: &RegisteredClient,
    request: AuthorizationRequest,
) -> Result<ValidatedAuthorizationRequest, AuthorizationRequestError> {
    let allowed_scopes = DEFAULT_ALLOWED_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect::<Vec<_>>();
    validate_authorization_request_with_allowlist(client, request, &allowed_scopes)
}

pub fn validate_authorization_request_with_allowlist(
    client: &RegisteredClient,
    request: AuthorizationRequest,
    allowed_scopes: &[String],
) -> Result<ValidatedAuthorizationRequest, AuthorizationRequestError> {
    if request.client_id != client.client_id {
        return Err(AuthorizationRequestError::InvalidClient);
    }
    let canonical_redirect_uri = canonicalize_redirect_uri(&request.redirect_uri)
        .ok_or(AuthorizationRequestError::RedirectUriNotAllowed)?;
    if !client
        .redirect_uris
        .iter()
        .any(|uri| redirect_uri_matches(uri, &canonical_redirect_uri))
    {
        return Err(AuthorizationRequestError::RedirectUriNotAllowed);
    }
    if request.response_type != "code" {
        return Err(AuthorizationRequestError::UnsupportedResponseType);
    }
    let scopes = request
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !scopes_are_allowed(client, &scopes, allowed_scopes) {
        return Err(AuthorizationRequestError::ScopeNotAllowed);
    }
    let state = request
        .state
        .filter(|state| !state.trim().is_empty())
        .ok_or(AuthorizationRequestError::MissingState)?;
    if state.chars().count() > MAX_STATE_LENGTH {
        return Err(AuthorizationRequestError::StateTooLong);
    }
    let nonce = request.nonce.filter(|nonce| !nonce.trim().is_empty());
    if nonce
        .as_ref()
        .is_some_and(|nonce| nonce.chars().count() > MAX_NONCE_LENGTH)
    {
        return Err(AuthorizationRequestError::NonceTooLong);
    }
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(AuthorizationRequestError::PkceRequired);
    }
    let Some(code_challenge) = request.code_challenge.as_deref() else {
        return Err(AuthorizationRequestError::PkceRequired);
    };
    if validate_s256_challenge(code_challenge).is_err() {
        return Err(AuthorizationRequestError::InvalidCodeChallenge);
    }

    Ok(ValidatedAuthorizationRequest {
        client_id: request.client_id,
        redirect_uri: canonical_redirect_uri,
        scopes,
        state,
        nonce,
        code_challenge: code_challenge.to_owned(),
        owner_user_id: Some(client.owner_user_id).flatten(),
        // 会话绑定由持有会话的调用方回填，见字段文档。
        session_token_hash: None,
    })
}

/// RFC 8252 section 7.3 permits native apps using a literal loopback address
/// to vary only the port between registration and authorization. All other
/// redirect URIs retain exact matching after canonicalization.
pub(crate) fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }

    let (Ok(registered_url), Ok(requested_url)) = (Url::parse(registered), Url::parse(requested))
    else {
        return false;
    };
    if registered_url.as_str() != registered || requested_url.as_str() != requested {
        return false;
    }
    if registered_url.scheme() != "http" || requested_url.scheme() != "http" {
        return false;
    }

    let same_literal_loopback_ip = match (registered_url.host(), requested_url.host()) {
        (Some(Host::Ipv4(registered_ip)), Some(Host::Ipv4(requested_ip))) => {
            registered_ip.is_loopback() && registered_ip == requested_ip
        }
        (Some(Host::Ipv6(registered_ip)), Some(Host::Ipv6(requested_ip))) => {
            registered_ip.is_loopback() && registered_ip == requested_ip
        }
        _ => false,
    };

    same_literal_loopback_ip
        && registered_url.username().is_empty()
        && requested_url.username().is_empty()
        && registered_url.password().is_none()
        && requested_url.password().is_none()
        && registered_url.path() == requested_url.path()
        && registered_url.query() == requested_url.query()
        && registered_url.fragment().is_none()
        && requested_url.fragment().is_none()
}

pub(crate) fn scopes_are_allowed(
    client: &RegisteredClient,
    scopes: &[String],
    allowed_scopes: &[String],
) -> bool {
    !scopes.is_empty()
        && scopes.iter().all(|scope| {
            allowed_scopes.iter().any(|allowed| allowed == scope)
                && client.scopes.iter().any(|registered| registered == scope)
        })
}
