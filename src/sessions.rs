//! Session lifecycle boundary with PostgreSQL authority and a Redis projection.

pub(crate) mod cookie_parse;
pub mod cookies;
pub(crate) mod crypto;
pub mod domain;
mod outbox;
pub mod store;

pub use outbox::{OutboxCleanup, SessionOutboxPolicy};
