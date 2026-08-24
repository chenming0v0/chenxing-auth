//! OAuth / OIDC / client / consent / token integration tests.
//!
//! Run with `test_sh/test.sh --test oauth`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;
#[path = "../support/plan_fixtures.rs"]
mod plan_fixtures;

mod access_token_revocation_durability;
mod api;
mod authorization_code;
mod authorization_code_issuer;
mod client_auth;
mod client_auth_method_secret;
mod client_credentials;
mod client_domain;
mod client_idempotency;
mod client_lifecycle;
mod client_secret_rotation;
mod client_secret_token_race;
mod clients;
mod consent_code_exchange_race;
mod consent_revocation_durability;
mod consents_service;
mod domain;
mod flow;
mod pkce;
mod provider_admin_api;
mod provider_domain;
mod provider_endpoint_policy;
mod provider_flow;
mod provider_pending_flow;
mod provider_proxy_boundary;
mod provider_secret_recovery;
mod quota;
mod refresh_token_security;
mod refresh_tokens;
mod request_rebinding;
mod revocation;
mod revocation_handler;
mod session_binding;
mod session_epoch_race;
mod session_token_race;
mod token_flow;
mod tokens;
mod ui_api;
mod ui_retry;
mod user_oauth_api;
mod userinfo;
