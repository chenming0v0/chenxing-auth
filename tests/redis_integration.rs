//! Redis-backed integration tests.
//!
//! Keeping these cases in a dedicated target makes `test_sh/test.sh --lib`
//! independent from PostgreSQL and Redis availability. Run them explicitly with
//! `test_sh/test.sh --test redis_integration` or as part of the full suite.

#[path = "redis_integration/auth_limiter.rs"]
mod auth_limiter;
#[path = "redis_integration/client.rs"]
mod client;
#[path = "redis_integration/external_login_state.rs"]
mod external_login_state;
#[path = "redis_integration/oauth_quota.rs"]
mod oauth_quota;
#[path = "redis_integration/oauth_quota_refund.rs"]
mod oauth_quota_refund;
#[path = "redis_integration/oauth_rate_limit.rs"]
mod oauth_rate_limit;
#[path = "redis_integration/oauth_request_store.rs"]
mod oauth_request_store;
#[path = "redis_integration/oauth_request_store_ttl.rs"]
mod oauth_request_store_ttl;
