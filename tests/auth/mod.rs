//! Login / TOTP / passkey / auth-factor integration tests.
//!
//! Run with `test_sh/test.sh --test auth`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;
#[path = "../support/totp_time.rs"]
mod totp_time;

mod browser_flow;
mod credentials;
mod factor_security_api;
mod factors_domain;
mod factors_repository;
mod factors_storage;
mod limiter;
mod login_authentication_epoch_race;
mod login_domain;
mod login_security;
mod login_ticket_epoch;
mod passkey_auth;
mod passkey_cas;
mod passkey_policy;
mod passkey_recovery;
mod passkey_rp_id_policy;
mod totp_auth;
mod totp_domain;
mod totp_enrollment_fallback;
mod totp_factor_race;
mod totp_key_retirement;
mod totp_replay;
