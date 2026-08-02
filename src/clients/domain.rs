use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub const DEFAULT_MAX_REDIRECT_URIS: usize = 10;
pub const DEFAULT_MAX_REDIRECT_URI_LENGTH: usize = 2_048;
pub const DEFAULT_MAX_SCOPES: usize = 32;
pub const DEFAULT_MAX_SCOPE_LENGTH: usize = 64;
pub const ABSOLUTE_MAX_REDIRECT_URIS: usize = 100;
pub const ABSOLUTE_MAX_REDIRECT_URI_LENGTH: usize = 8_192;
pub const ABSOLUTE_MAX_SCOPES: usize = 100;
pub const ABSOLUTE_MAX_SCOPE_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationLimits {
    pub max_redirect_uris: usize,
    pub max_redirect_uri_length: usize,
    pub max_scopes: usize,
    pub max_scope_length: usize,
}

impl Default for ClientRegistrationLimits {
    fn default() -> Self {
        Self {
            max_redirect_uris: DEFAULT_MAX_REDIRECT_URIS,
            max_redirect_uri_length: DEFAULT_MAX_REDIRECT_URI_LENGTH,
            max_scopes: DEFAULT_MAX_SCOPES,
            max_scope_length: DEFAULT_MAX_SCOPE_LENGTH,
        }
    }
}

impl ClientRegistrationLimits {
    pub fn new(
        max_redirect_uris: usize,
        max_redirect_uri_length: usize,
        max_scopes: usize,
        max_scope_length: usize,
    ) -> Option<Self> {
        if max_redirect_uris == 0
            || max_redirect_uris > ABSOLUTE_MAX_REDIRECT_URIS
            || max_redirect_uri_length == 0
            || max_redirect_uri_length > ABSOLUTE_MAX_REDIRECT_URI_LENGTH
            || max_scopes == 0
            || max_scopes > ABSOLUTE_MAX_SCOPES
            || max_scope_length == 0
            || max_scope_length > ABSOLUTE_MAX_SCOPE_LENGTH
        {
            return None;
        }
        Some(Self {
            max_redirect_uris,
            max_redirect_uri_length,
            max_scopes,
            max_scope_length,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ClientRegistrationInput {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

pub type ClientUpdateInput = ClientRegistrationInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClientRegistration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientRegistrationError {
    #[error("client name is invalid")]
    InvalidClientName,
    #[error("at least one redirect URI is required")]
    MissingRedirectUri,
    #[error("too many redirect URIs")]
    TooManyRedirectUris,
    #[error("redirect URI is too long")]
    RedirectUriTooLong,
    #[error("redirect URI must use HTTPS")]
    InsecureRedirectUri,
    #[error("wildcard redirect URI is not allowed")]
    WildcardRedirectUri,
    #[error("redirect URI is invalid")]
    InvalidRedirectUri,
    #[error("at least one scope is required")]
    MissingScope,
    #[error("too many scopes")]
    TooManyScopes,
    #[error("scope is too long")]
    ScopeTooLong,
    #[error("scope is invalid")]
    InvalidScope,
}

pub fn validate_client_registration(
    input: ClientRegistrationInput,
) -> Result<ValidatedClientRegistration, ClientRegistrationError> {
    validate_client_registration_with_limits(input, &ClientRegistrationLimits::default())
}

pub fn validate_client_registration_with_limits(
    input: ClientRegistrationInput,
    limits: &ClientRegistrationLimits,
) -> Result<ValidatedClientRegistration, ClientRegistrationError> {
    let client_name = input.client_name.trim().to_owned();
    if client_name.is_empty() || client_name.chars().count() > 128 {
        return Err(ClientRegistrationError::InvalidClientName);
    }
    if input.redirect_uris.is_empty() {
        return Err(ClientRegistrationError::MissingRedirectUri);
    }
    if input.redirect_uris.len() > limits.max_redirect_uris {
        return Err(ClientRegistrationError::TooManyRedirectUris);
    }

    let redirect_uris = input
        .redirect_uris
        .into_iter()
        .map(|redirect_uri| validate_redirect_uri(redirect_uri, limits))
        .collect::<Result<Vec<_>, _>>()?;

    if input.scopes.is_empty() {
        return Err(ClientRegistrationError::MissingScope);
    }
    if input.scopes.len() > limits.max_scopes {
        return Err(ClientRegistrationError::TooManyScopes);
    }
    let scopes = input
        .scopes
        .into_iter()
        .map(|scope| {
            let scope = scope.trim().to_owned();
            if scope.chars().count() > limits.max_scope_length {
                return Err(ClientRegistrationError::ScopeTooLong);
            }
            if scope.is_empty() || scope.chars().any(char::is_whitespace) {
                Err(ClientRegistrationError::InvalidScope)
            } else {
                Ok(scope)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Duplicate values are accepted and normalized in first-seen order.
    let redirect_uris = deduplicate(redirect_uris);
    let scopes = deduplicate(scopes);

    Ok(ValidatedClientRegistration {
        client_name,
        redirect_uris,
        scopes,
    })
}

fn validate_redirect_uri(
    value: String,
    limits: &ClientRegistrationLimits,
) -> Result<String, ClientRegistrationError> {
    let value = value.trim().to_owned();
    if value.chars().count() > limits.max_redirect_uri_length {
        return Err(ClientRegistrationError::RedirectUriTooLong);
    }
    if value.contains('*') {
        return Err(ClientRegistrationError::WildcardRedirectUri);
    }
    let url = Url::parse(&value).map_err(|_| ClientRegistrationError::InvalidRedirectUri)?;
    if url.scheme() != "https" {
        return Err(ClientRegistrationError::InsecureRedirectUri);
    }
    if url.host_str().is_none() || url.fragment().is_some() {
        return Err(ClientRegistrationError::InvalidRedirectUri);
    }
    if url.username() != "" || url.password().is_some() {
        return Err(ClientRegistrationError::InvalidRedirectUri);
    }
    Ok(value)
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        if !unique.contains(&value) {
            unique.push(value);
        }
        unique
    })
}
