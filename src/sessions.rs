//! Session lifecycle boundary with PostgreSQL authority and a Redis projection.

pub mod cookies;
pub(crate) mod crypto;
pub mod domain;
mod external_state;
mod outbox;
pub mod store;

pub use outbox::{OutboxCleanup, SessionOutboxPolicy};
