//! Sanitized error classification for the template database fixture.
//!
//! The error intentionally exposes only a typed classification, a static
//! operation name, and — when the server reported one — the five-character
//! SQLSTATE. It never carries a raw SQLx message, a connection URL, a password,
//! an option string, or a source chain, so it is safe to print from an example
//! or a panicking fixture.

use std::fmt;

/// Typed failure classification for template database operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbTestError {
    /// A required environment variable is missing or empty.
    MissingEnv(&'static str),
    /// A name failed the frozen namespace grammar.
    InvalidName(&'static str),
    /// A database URL is malformed or lacks an explicit database name.
    InvalidUrl(&'static str),
    /// The requested name is a protected target (template, clone, or builtin).
    ProtectedDatabase,
    /// A name that must not exist already exists.
    NameCollision(&'static str),
    /// The live database or role disagrees with the configured source.
    SourceMismatch(&'static str),
    /// The current role is not the owner needed for the operation.
    RoleNotOwner(&'static str),
    /// A database statement failed; `sqlstate` is the sanitized SQLSTATE code.
    DatabaseOperation {
        operation: &'static str,
        sqlstate: Option<String>,
    },
    /// Sessions remained on a database that must be free of connections.
    SessionsRemain(&'static str),
    /// A returned pool did not point at the expected database or schema.
    PoolInvariant(&'static str),
}

impl fmt::Display for DbTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnv(name) => {
                write!(formatter, "missing required environment variable {name}")
            }
            Self::InvalidName(what) => write!(formatter, "invalid database name: {what}"),
            Self::InvalidUrl(what) => write!(formatter, "invalid database URL: {what}"),
            Self::ProtectedDatabase => {
                write!(formatter, "refusing to touch a protected database")
            }
            Self::NameCollision(what) => {
                write!(formatter, "database name already exists: {what}")
            }
            Self::SourceMismatch(what) => {
                write!(formatter, "source database or role mismatch: {what}")
            }
            Self::RoleNotOwner(what) => {
                write!(formatter, "current role is not the owner: {what}")
            }
            Self::DatabaseOperation {
                operation,
                sqlstate,
            } => match sqlstate {
                Some(code) => {
                    write!(
                        formatter,
                        "database operation {operation} failed (SQLSTATE {code})"
                    )
                }
                None => write!(formatter, "database operation {operation} failed"),
            },
            Self::SessionsRemain(what) => {
                write!(formatter, "sessions remained on {what}")
            }
            Self::PoolInvariant(what) => write!(formatter, "pool invariant violated: {what}"),
        }
    }
}

impl std::error::Error for DbTestError {}

/// Extract a sanitized SQLSTATE code from a SQLx error.
///
/// Only a well-formed five-character alphanumeric code is kept; anything else
/// (including any human-readable message) is discarded.
pub(crate) fn sqlstate(error: &chenxing_auth::sqlx::Error) -> Option<String> {
    let code = error.as_database_error()?.code()?;
    let code = code.as_ref();
    (code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| code.to_owned())
}

/// Classify a SQLx failure as a sanitized database operation error.
pub(crate) fn database_error(
    operation: &'static str,
    error: &chenxing_auth::sqlx::Error,
) -> DbTestError {
    DbTestError::DatabaseOperation {
        operation,
        sqlstate: sqlstate(error),
    }
}
