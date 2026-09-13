#![allow(dead_code)]

//! Shared test-only template database support (issue #710 stage 1).
//!
//! This module is compiled into the integration test support layer and into the
//! `test_database` example via `#[path]`. It is a self-contained module tree: it
//! has no test functions of its own, and every pure test lives once in
//! `tests/platform/support_contract.rs`.
//!
//! The public surface is frozen (see the stage 1 contract). In particular:
//! `Namespace`, `DatabaseName`, `TemplateConfig`, and `DbTestError` are the only
//! types other code may depend on. `quote_identifier` and
//! `TemplateConfig::owner_options_for` are crate-internal helpers used by the
//! lifecycle tests.

mod clone;
pub mod config;
pub mod error;
pub mod lifecycle;
pub mod names;

// The facade is a frozen public surface consumed by several compilation units
// with different needs: `test_database` uses only `TemplateConfig`, the test
// support layer uses the namespace/name types, and other targets import none of
// them. `TemplateConfig` is referenced by the shared fixture in every consumer,
// but the remaining re-exports are unused in some consumers, so those carry a
// targeted allow. The underlying modules keep normal unused-import checking.
pub use config::TemplateConfig;
#[allow(unused_imports)]
pub use error::DbTestError;
#[allow(unused_imports)]
pub use lifecycle::CleanupSummary;
#[allow(unused_imports)]
pub use names::{
    DATABASE_PREFIX_ENV, DatabaseName, Namespace, OWNER_DATABASE_URL_ENV, RUNTIME_DATABASE_URL_ENV,
    TEMPLATE_DATABASE_ENV,
};
