//! OAuth 2.0 and OpenID Connect protocol integration boundary.
//!
//! Protocol behavior must be built on a mature Rust protocol library instead
//! of reimplementing token signing or protocol parsing here.

pub mod authorization;
pub mod authorization_code_handlers;
pub mod client_auth;
pub mod code;
pub mod consent;
mod form;
pub mod handlers;
pub mod id_token;
pub mod pkce;
pub mod providers;
pub mod quota;
pub mod rate_limit;
pub mod refresh;
pub mod refresh_store;
pub mod request_store;
mod request_store_scripts;
pub mod response;
pub mod revocation;
pub mod revocation_handler;
pub mod session;
pub mod store;
pub mod token;
pub mod token_handlers;
pub mod token_security;
pub mod ui_handlers;
pub mod userinfo;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub revocation_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
}

impl OpenIdConfiguration {
    pub fn for_issuer(issuer: &str) -> Self {
        let issuer = issuer.trim_end_matches('/').to_owned();
        Self {
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
            revocation_endpoint: format!("{issuer}/oauth/revoke"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            issuer,
            response_types_supported: vec!["code"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            scopes_supported: vec!["openid", "profile", "email"],
            claims_supported: vec!["sub", "iss", "aud", "exp", "iat", "email", "name"],
            code_challenge_methods_supported: vec!["S256"],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
        }
    }
}
