pub mod admin;
pub mod api;
pub mod audit;
pub mod auth_factors;
pub mod auth_limiter;
pub mod clients;
pub mod clock;
pub mod config;
pub mod consents;
pub mod db;
pub mod error;
pub mod extensions;
pub mod invitation_codes;
mod key_storage;
pub mod keys;
pub mod oauth;
pub mod plans;
pub mod redis_client;
pub mod redis_keyspace;
pub mod sessions;
pub mod settings;
pub mod shutdown;
pub mod state;
pub mod users;
pub mod web_dist;
pub mod workers;

pub mod sqlx {
    pub use sqlx_core::acquire::Acquire;
    pub use sqlx_core::connection::Connection;
    pub use sqlx_core::executor::Executor;
    pub use sqlx_core::from_row::FromRow;
    pub use sqlx_core::pool::{Pool, PoolConnection};
    pub use sqlx_core::query::query;
    pub use sqlx_core::query_as::query_as;
    pub use sqlx_core::query_scalar::query_scalar;
    pub use sqlx_core::transaction::Transaction;
    pub use sqlx_core::{Error, Result, acquire, error::DatabaseError, from_row, migrate, types};
    pub use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions, Postgres};

    pub mod postgres {
        pub use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions, Postgres};
    }
}

pub const SERVICE_NAME: &str = "chenxing-auth";
