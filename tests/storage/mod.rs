//! Database / Redis / key / plan / migration integration tests.
//!
//! Run with `test_sh/test.sh --test storage`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/plans.rs"]
mod plans_support;

#[path = "db_isolation.rs"]
mod database_isolation;
mod database_schema;
mod integration;
mod jsonb_oauth_consent_shapes;
mod key_persistence;
mod keys;
mod migration_upgrade;
mod plans;
mod redis;
mod redis_namespace_isolation;
