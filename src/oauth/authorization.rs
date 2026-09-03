use super::pkce::validate_s256_challenge;
use crate::clients::domain::{DEFAULT_ALLOWED_SCOPES, canonicalize_redirect_uri};
use crate::users::domain::UserId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use url::{Host, Url};

/// Maximum number of Unicode scalar values accepted for the OAuth `state` value.
pub const MAX_STATE_LENGTH: usize = 512;
/// Maximum number of Unicode scalar values accepted for the OIDC `nonce` value.
pub const MAX_NONCE_LENGTH: usize = 512;
/// `max_age` is compared against Unix seconds, so values outside the signed
/// timestamp range cannot be represented safely by the shared clock.
pub const MAX_MAX_AGE: u64 = i64::MAX as u64;

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
    /// OpenID Connect Core `prompt` values, separated by spaces.
    pub prompt: Option<String>,
    /// Maximum permitted age of the authentication event, in seconds.
    pub max_age: Option<u64>,
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
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
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
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    pub client_id: String,
    /// 授权请求提交的原始 `redirect_uri` 文本。
    ///
    /// 注册匹配使用 canonical 形式，但授权码必须绑定这份原始文本；Token
    /// 端点只接受同一原始值，不能把 `:443`、根斜杠等文本差异再规范化掉。
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    /// Normalized OIDC `prompt` value. `None` means the default prompt policy.
    pub prompt: Option<String>,
    pub max_age: Option<u64>,
    /// Set by the authorization handler when the request requires a fresh
    /// login. The optional hash identifies the pre-existing session that must
    /// not satisfy the request by itself.
    pub reauth_required: bool,
    pub reauth_session_token_hash: Option<String>,
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
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("reauth_required", &self.reauth_required)
            .field(
                "reauth_session_token_hash",
                &self
                    .reauth_session_token_hash
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
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
    #[error("prompt is invalid")]
    InvalidPrompt,
    #[error("prompt=none cannot be combined with another prompt value")]
    PromptNoneCombined,
    #[error("max_age is too large")]
    MaxAgeTooLarge,
    #[error("PKCE S256 is required")]
    PkceRequired,
    #[error("PKCE S256 challenge is invalid")]
    InvalidCodeChallenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PromptOptions {
    pub login: bool,
    pub none: bool,
    pub consent: bool,
    pub select_account: bool,
}

impl PromptOptions {
    pub fn parse(value: Option<&str>) -> Result<(Self, Option<String>), AuthorizationRequestError> {
        let Some(value) = value else {
            return Ok((Self::default(), None));
        };
        let mut seen = HashSet::new();
        let mut options = Self::default();
        let mut normalized = Vec::new();
        for token in value.split_whitespace() {
            if !seen.insert(token) {
                return Err(AuthorizationRequestError::InvalidPrompt);
            }
            match token {
                "login" => options.login = true,
                "none" => options.none = true,
                "consent" => options.consent = true,
                "select_account" => options.select_account = true,
                _ => return Err(AuthorizationRequestError::InvalidPrompt),
            }
            normalized.push(token);
        }
        if normalized.is_empty() {
            return Err(AuthorizationRequestError::InvalidPrompt);
        }
        if options.none && normalized.len() > 1 {
            return Err(AuthorizationRequestError::PromptNoneCombined);
        }
        Ok((options, Some(normalized.join(" "))))
    }

    pub fn requires_login(self) -> bool {
        self.login
    }

    pub fn requires_consent(self) -> bool {
        self.consent
    }

    pub fn requires_account_selection(self) -> bool {
        self.select_account
    }
}

/// Returns whether a session's authentication event satisfies `max_age`.
/// `max_age=0` intentionally never accepts an existing session: it is the
/// OIDC step-up/re-authentication boundary, even within the same Unix second.
pub fn authentication_is_fresh(
    created_at: OffsetDateTime,
    now: OffsetDateTime,
    max_age: Option<u64>,
) -> bool {
    let Some(max_age) = max_age else {
        return true;
    };
    if max_age == 0 {
        return false;
    }
    let elapsed = now
        .unix_timestamp()
        .saturating_sub(created_at.unix_timestamp());
    elapsed >= 0 && (elapsed as u64) <= max_age
}

/// Returns whether the current session satisfies a pending re-authentication
/// requirement and its optional `max_age` bound.
///
/// `prompt=login` and `max_age` requests retain the pre-existing session hash
/// as a fence. A changed hash proves that the login flow issued a different
/// session; that new session satisfies `max_age=0` even when both sessions were
/// created in the same Unix second. Positive `max_age` values still require
/// the new session's authentication event to be within the requested window.
pub fn reauthentication_is_satisfied(
    current_session_token_hash: &str,
    previous_session_token_hash: Option<&str>,
    created_at: OffsetDateTime,
    now: OffsetDateTime,
    max_age: Option<u64>,
    reauth_required: bool,
) -> bool {
    if !reauth_required {
        return authentication_is_fresh(created_at, now, max_age);
    }
    if previous_session_token_hash.is_some_and(|previous| previous == current_session_token_hash) {
        return false;
    }
    if created_at.unix_timestamp() > now.unix_timestamp() {
        return false;
    }
    if max_age == Some(0) {
        return true;
    }
    authentication_is_fresh(created_at, now, max_age)
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
    let (_prompt_options, prompt) = PromptOptions::parse(request.prompt.as_deref())?;
    if request.max_age.is_some_and(|max_age| max_age > MAX_MAX_AGE) {
        return Err(AuthorizationRequestError::MaxAgeTooLarge);
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
        redirect_uri: request.redirect_uri,
        scopes,
        state,
        nonce,
        code_challenge: code_challenge.to_owned(),
        prompt,
        max_age: request.max_age,
        reauth_required: false,
        reauth_session_token_hash: None,
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

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationRequestError, PromptOptions, authentication_is_fresh,
        reauthentication_is_satisfied,
    };
    use time::{Duration, OffsetDateTime};

    #[test]
    fn prompt_parser_accepts_supported_values_and_rejects_duplicates() {
        let (options, normalized) =
            PromptOptions::parse(Some("login consent")).expect("supported prompt values");
        assert!(options.login && options.consent);
        assert_eq!(normalized.as_deref(), Some("login consent"));
        assert_eq!(
            PromptOptions::parse(Some("login login")).expect_err("duplicate prompt"),
            AuthorizationRequestError::InvalidPrompt
        );
    }

    #[test]
    fn prompt_none_cannot_be_combined_with_interaction() {
        assert_eq!(
            PromptOptions::parse(Some("none login")).expect_err("illegal prompt combination"),
            AuthorizationRequestError::PromptNoneCombined
        );
    }

    #[test]
    fn max_age_zero_always_requires_reauthentication() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(100);
        assert!(!authentication_is_fresh(now, now, Some(0)));
        assert!(authentication_is_fresh(
            now - Duration::seconds(30),
            now,
            Some(30)
        ));
        assert!(!authentication_is_fresh(
            now - Duration::seconds(31),
            now,
            Some(30)
        ));
    }

    #[test]
    fn reauthentication_fence_accepts_a_new_session_for_zero_max_age() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(100);
        assert!(reauthentication_is_satisfied(
            "new-session",
            Some("old-session"),
            now,
            now,
            Some(0),
            true,
        ));
        assert!(!reauthentication_is_satisfied(
            "old-session",
            Some("old-session"),
            now,
            now,
            Some(0),
            true,
        ));
        assert!(reauthentication_is_satisfied(
            "new-session",
            None,
            now,
            now,
            Some(0),
            true,
        ));
        assert!(!reauthentication_is_satisfied(
            "new-session",
            Some("old-session"),
            now + Duration::seconds(1),
            now,
            Some(0),
            true,
        ));
    }
}
