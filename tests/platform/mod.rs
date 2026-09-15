//! HTTP / OpenAPI / config / deployment / web-bundle integration tests.
//!
//! Run with `test_sh/test.sh --test platform`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/harness.rs"]
mod harness;
#[path = "../support/http.rs"]
mod http;
#[path = "../support/key_directory.rs"]
mod key_directory;
#[path = "../support/oauth_flow.rs"]
mod oauth_flow;

mod api;
mod build_logic;
mod config;
mod config_examples;
mod config_startup_warnings;
mod db_timing_contract;
mod deployment;
mod extensions;
mod http_error_contract;
mod http_shutdown;
mod openapi_contract;
mod protected_api;
mod support_contract;
mod template_lifecycle;
mod web;
