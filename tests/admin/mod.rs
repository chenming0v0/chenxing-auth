//! Admin / owner / issuer / audit integration tests.
//!
//! Run with `test_sh/test.sh --test admin`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;
#[path = "../support/plan_fixtures.rs"]
mod plan_fixtures;

mod api;
mod audit;
mod audit_archive_insert_boundary;
mod audit_effective_role;
mod authorization_audit;
mod bootstrap_invariant;
mod core;
mod domain;
mod issuer;
mod issuer_routes;
mod issuer_settings;
mod management_session_bind;
mod owner_login_flow;
mod owner_write_race;
mod privileged_audit;
mod registration_settings;
mod role_generation;
mod settings;
mod settings_diagnostic;
mod smtp_password;
mod system_settings;
mod token_disabled;
mod ui_api;
mod write_actor_race;
