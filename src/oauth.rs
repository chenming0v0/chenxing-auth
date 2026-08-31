//! OAuth 2.0 and OpenID Connect protocol integration boundary.
//!
//! Protocol behavior must be built on a mature Rust protocol library instead
//! of reimplementing token signing or protocol parsing here.

mod access_token_revocation;
pub mod authorization;
pub mod authorization_code_handlers;
pub mod authorization_decision_use_case;
mod cas;
pub mod client_auth;
pub mod code;
pub mod consent;
pub mod consent_cache;
mod consent_cache_scripts;
mod form;
mod grant_gate;
pub mod handlers;
pub mod id_token;
mod issuance_fence;
pub mod pkce;
pub mod providers;
pub mod quota;
mod quota_scripts;
pub mod rate_limit;
pub mod refresh;
pub mod refresh_grant;
pub mod refresh_store;
mod refresh_store_scripts;
pub mod refresh_tombstone;
pub(crate) mod request_binding;
pub mod request_store;
mod request_store_scripts;
pub mod response;
pub mod revocation;
pub mod revocation_handler;
pub mod revoke_consent_use_case;
pub mod session;
pub mod store;
pub mod token;
pub mod token_handlers;
pub mod token_security;
pub mod token_use_case;
pub mod ui_handlers;
mod ui_responses;
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
    pub prompt_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
}

impl OpenIdConfiguration {
    pub fn for_issuer(issuer: &str) -> Self {
        let scopes = crate::clients::domain::DEFAULT_ALLOWED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<Vec<_>>();
        Self::for_issuer_with_scopes(issuer, &scopes)
    }

    pub fn for_issuer_with_scopes(issuer: &str, scopes_supported: &[String]) -> Self {
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
            prompt_values_supported: vec!["login", "none", "consent", "select_account"],
            scopes_supported: scopes_supported.to_owned(),
            // `nonce` 在实际签发的 ID Token 中出现（有会话时）；`auth_time` 同样
            // 已实现。`azp` 未实现（单 audience 场景可省略，OIDC Core §2 允许），
            // 故不声明，避免制造新的不一致。
            claims_supported: vec![
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "email",
                "name",
                "nonce",
                "auth_time",
            ],
            code_challenge_methods_supported: vec!["S256"],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            revocation_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
        }
    }
}
