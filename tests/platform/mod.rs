//! HTTP / OpenAPI / config / deployment / web-bundle integration tests.
//!
//! Run with `test_sh/test.sh --test platform`.

#[path = "../support/db_isolation.rs"]
mod db_isolation;
#[path = "../support/key_directory.rs"]
mod key_directory;

mod api;
mod build_logic;
mod config;
mod config_examples;
mod config_startup_warnings;
mod deployment;
mod extensions;
mod http_error_contract;
mod http_shutdown;
mod openapi_contract;
mod protected_api;
mod web;
