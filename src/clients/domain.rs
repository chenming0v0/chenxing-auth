use serde::Deserialize;
use thiserror::Error;
use url::Url;

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
    #[error("redirect URI must use HTTPS")]
    InsecureRedirectUri,
    #[error("wildcard redirect URI is not allowed")]
    WildcardRedirectUri,
    #[error("redirect URI is invalid")]
    InvalidRedirectUri,
    #[error("at least one scope is required")]
    MissingScope,
    #[error("scope is invalid")]
    InvalidScope,
}

pub fn validate_client_registration(
    input: ClientRegistrationInput,
) -> Result<ValidatedClientRegistration, ClientRegistrationError> {
    let client_name = input.client_name.trim().to_owned();
    if client_name.is_empty() || client_name.chars().count() > 128 {
        return Err(ClientRegistrationError::InvalidClientName);
    }
    if input.redirect_uris.is_empty() {
        return Err(ClientRegistrationError::MissingRedirectUri);
    }

    let redirect_uris = input
        .redirect_uris
        .into_iter()
        .map(validate_redirect_uri)
        .collect::<Result<Vec<_>, _>>()?;

    if input.scopes.is_empty() {
        return Err(ClientRegistrationError::MissingScope);
    }
    let scopes = input
        .scopes
        .into_iter()
        .map(|scope| {
            let scope = scope.trim().to_owned();
            if scope.is_empty() || scope.chars().any(char::is_whitespace) {
                Err(ClientRegistrationError::InvalidScope)
            } else {
                Ok(scope)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let scopes = deduplicate(scopes);

    Ok(ValidatedClientRegistration {
        client_name,
        redirect_uris,
        scopes,
    })
}

fn validate_redirect_uri(value: String) -> Result<String, ClientRegistrationError> {
    let value = value.trim().to_owned();
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
