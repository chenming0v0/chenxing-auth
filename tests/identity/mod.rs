//! Session / CSRF / cookie / user-profile integration tests.
//!
//! Run with `test_sh/test.sh --test identity`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;

mod cookie_security;
mod csrf;
mod csrf_route_coverage;
mod email_change_attempt_budget;
mod email_change_outbox;
mod external_identity_binding;
mod security_events_api;
mod session_api;
mod session_auth_role_bind;
mod session_outbox_retention;
mod session_payload_identity;
mod sessions;
mod user_avatar_api;
mod user_profile_security_api;
mod user_sessions_api;
mod users;
mod users_canonical_email;
