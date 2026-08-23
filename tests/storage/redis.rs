//! Redis-backed integration tests.
//!
//! Keeping these cases in a dedicated module makes `test_sh/test.sh --lib`
//! independent from PostgreSQL and Redis availability. Run them with
//! `test_sh/test.sh --test storage` or as part of the full suite.

mod auth_limiter;
mod client;
mod external_login_state;
mod oauth_cas;
mod oauth_quota;
mod oauth_quota_refund;
mod oauth_rate_limit;
mod oauth_request_store;
mod oauth_request_store_ttl;
