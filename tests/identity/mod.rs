//! Session / CSRF / cookie / user-profile integration tests.
//!
//! Run with `test_sh/test.sh --test identity`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;

mod account_provider_registry;
mod cookie_security;
mod csrf;
mod csrf_route_coverage;
// Issue #706：CLtermux 业务账号绑定（bind/refresh/delete + resolve）。
mod cltermux_resolve;
// Issue #709：辰星 Access Token 兑换 CLtermux 业务会话令牌。
mod cltermux_exchange;
mod email_change_attempt_budget;
mod email_change_outbox;
mod external_identity_binding;
mod linked_accounts_cltermux;
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
