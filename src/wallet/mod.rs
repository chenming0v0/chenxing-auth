//! Internal 辰星点 wallet and self-serve plan purchase.
//!
//! Wallets are lazy: a `user_wallets` row is created on first credit or
//! purchase, not at user registration. GET returns balance 0 when no row
//! exists. Debit and credit share one `SELECT FOR UPDATE` so concurrent
//! purchases cannot drive the balance negative.
//!
//! Asset and entitlement mutations carry the exact request Session into the
//! database transaction. They validate it once while acquiring the user/session
//! fence, then again after every resource lock and immediately before the first
//! wallet, redemption, or entitlement write (Issue #704). Ordinary profile
//! changes intentionally keep request-entry Session validation only.

pub mod domain;
pub mod handlers;
pub mod redemption_domain;
pub mod redemption_handlers;
pub mod redemption_repository;
pub mod redemption_service;
pub mod repository;
pub mod service;
