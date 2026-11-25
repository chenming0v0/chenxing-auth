use super::pkce::validate_s256_challenge;
use crate::clients::domain::DEFAULT_ALLOWED_SCOPES;
use std::collections::HashSet;
use time::OffsetDateTime;

mod redirect;
mod types;

pub(crate) use redirect::{redirect_uri_matches, validate_client_and_redirect_uri};
pub use types::{
    AuthorizationRequest, AuthorizationRequestError, MAX_MAX_AGE, MAX_NONCE_LENGTH,
    MAX_STATE_LENGTH, RegisteredClient, ValidatedAuthorizationRequest,
};

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
    validate_client_and_redirect_uri(client, &request)?;
    validate_supported_parameters(&request)?;
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

fn validate_supported_parameters(
    request: &AuthorizationRequest,
) -> Result<(), AuthorizationRequestError> {
    // RFC 6749 §3.1：空值参数视为未提供；非空的 Request Object 参数按 OIDC §6 拒绝。
    if request
        .request
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(AuthorizationRequestError::RequestNotSupported);
    }
    if request
        .request_uri
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(AuthorizationRequestError::RequestUriNotSupported);
    }
    if request
        .response_mode
        .as_deref()
        .is_some_and(|mode| !mode.is_empty() && mode != "query")
    {
        return Err(AuthorizationRequestError::UnsupportedResponseMode);
    }
    Ok(())
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
mod tests;
