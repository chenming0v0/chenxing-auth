use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine, engine::general_purpose::STANDARD};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientCredentialError {
    #[error("client authentication methods must not be combined")]
    MultipleMethods,
    #[error("client credentials are missing")]
    Missing,
    #[error("client credentials are invalid")]
    Invalid,
}

pub fn resolve_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<ClientCredentials, ClientCredentialError> {
    let form_has_credentials = form_client_id.is_some_and(|value| !value.is_empty())
        || form_client_secret.is_some_and(|value| !value.is_empty());
    let basic = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, encoded) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("Basic").then_some(encoded)
        });

    if basic.is_some() && form_has_credentials {
        return Err(ClientCredentialError::MultipleMethods);
    }
    if let Some(encoded) = basic {
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| ClientCredentialError::Invalid)?;
        let value = String::from_utf8(decoded).map_err(|_| ClientCredentialError::Invalid)?;
        let (client_id, client_secret) = value
            .split_once(':')
            .ok_or(ClientCredentialError::Invalid)?;
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(ClientCredentialError::Invalid);
        }
        return Ok(ClientCredentials {
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
        });
    }

    match (form_client_id, form_client_secret) {
        (Some(client_id), Some(client_secret))
            if !client_id.is_empty() && !client_secret.is_empty() =>
        {
            Ok(ClientCredentials {
                client_id: client_id.to_owned(),
                client_secret: client_secret.to_owned(),
            })
        }
        _ => Err(ClientCredentialError::Missing),
    }
}
