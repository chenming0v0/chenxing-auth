//! Frozen namespace grammar for template-database test isolation (issue #710).
//!
//! The grammar is intentionally strict and non-normalizing: nothing is trimmed,
//! lowercased, or truncated. A name either matches the whole grammar or it is a
//! near-match that every destructive path must leave untouched.

use sha2::{Digest, Sha256};

use super::error::DbTestError;

/// Environment variable holding the prepared template database name.
pub const TEMPLATE_DATABASE_ENV: &str = "CHENXING_TEST_TEMPLATE_DATABASE";
/// Environment variable holding the `ctest_<token>_` namespace prefix.
pub const DATABASE_PREFIX_ENV: &str = "CHENXING_TEST_DATABASE_PREFIX";
/// Environment variable holding the owner/migration connection URL.
pub const OWNER_DATABASE_URL_ENV: &str = "MIGRATION_DATABASE_URL";
/// Environment variable holding the optional runtime connection URL.
pub const RUNTIME_DATABASE_URL_ENV: &str = "DATABASE_URL";

const PREFIX_HEAD: &str = "ctest_";
const PREFIX_TAIL: char = '_';
const TEMPLATE_SUFFIX: &str = "template";
const CLONE_HASH_BYTES: usize = 8;
const CLONE_HASH_HEX_LEN: usize = CLONE_HASH_BYTES * 2;

/// A PostgreSQL database name validated for safe use as an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseName(String);

impl DatabaseName {
    /// Validate a name: non-empty, at most 63 bytes, no NUL byte.
    pub(crate) fn new_validated(name: &str) -> Result<Self, DbTestError> {
        if name.is_empty() || name.len() > 63 || name.contains('\0') {
            return Err(DbTestError::InvalidName("database name"));
        }
        Ok(Self(name.to_owned()))
    }

    /// The raw database name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated `ctest_<token>_` test namespace and its template database.
#[derive(Debug, Clone)]
pub struct Namespace {
    template: DatabaseName,
    prefix: String,
}

impl Namespace {
    /// Build a namespace from an explicit template name and prefix.
    ///
    /// `template` must equal `prefix + "template"` exactly; the prefix must be a
    /// 12..=36 byte `ctest_<token>_` string whose token starts and ends with a
    /// lowercase letter or digit and otherwise contains only `[a-z0-9_]`.
    pub fn new(template: &str, prefix: &str) -> Result<Self, DbTestError> {
        validate_prefix(prefix)?;
        let expected_template = format!("{prefix}{TEMPLATE_SUFFIX}");
        if template != expected_template {
            return Err(DbTestError::InvalidName(
                "template must equal prefix + template",
            ));
        }
        Ok(Self {
            template: DatabaseName::new_validated(template)?,
            prefix: prefix.to_owned(),
        })
    }

    /// The template database name for this namespace.
    pub fn template_name(&self) -> &DatabaseName {
        &self.template
    }

    /// The validated `ctest_<token>_` prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Derive the deterministic clone name for one fixture invocation.
    ///
    /// `prefix + first16 lowercasehex(SHA256(label\0identity\0pid)) + "_" + pid`.
    /// The PID must be a non-zero `u32` rendered canonically (no leading zeros).
    pub fn clone_name(
        &self,
        binary_label: &str,
        identity: &str,
        pid: u32,
    ) -> Result<DatabaseName, DbTestError> {
        if pid == 0 {
            return Err(DbTestError::InvalidName("clone pid must be non-zero"));
        }
        let mut hasher = Sha256::new();
        hasher.update(binary_label.as_bytes());
        hasher.update([0_u8]);
        hasher.update(identity.as_bytes());
        hasher.update([0_u8]);
        hasher.update(pid.to_string().as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest[..CLONE_HASH_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        DatabaseName::new_validated(&format!("{}{hex}_{pid}", self.prefix))
    }

    /// Whether `name` matches the entire clone grammar for this namespace.
    ///
    /// This is a full-suffix grammar check, not a prefix test or a SQL `LIKE`:
    /// lookalikes (bad PID spelling, wrong hash length, non-lowercase hex, extra
    /// suffixes) return `false` and must never be treated as owned.
    pub fn is_copy_name(&self, name: &str) -> bool {
        let Some(rest) = name.strip_prefix(self.prefix.as_str()) else {
            return false;
        };
        let Some((hex, pid)) = rest.split_once('_') else {
            return false;
        };
        if hex.len() != CLONE_HASH_HEX_LEN
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return false;
        }
        if pid.is_empty() || pid.len() > 10 {
            return false;
        }
        let Ok(parsed) = pid.parse::<u32>() else {
            return false;
        };
        parsed != 0 && parsed.to_string() == pid
    }

    /// Validate a source database name: non-empty, in bounds, and not part of
    /// the template/copy set owned by this namespace.
    pub fn validate_source_name(&self, name: &str) -> Result<(), DbTestError> {
        if name.is_empty() || name.len() > 63 || name.contains('\0') {
            return Err(DbTestError::InvalidName("source database name"));
        }
        if name == self.template.as_str() || self.is_copy_name(name) {
            return Err(DbTestError::ProtectedDatabase);
        }
        Ok(())
    }
}

fn validate_prefix(prefix: &str) -> Result<(), DbTestError> {
    if prefix.len() < 12 || prefix.len() > 36 {
        return Err(DbTestError::InvalidName("namespace prefix length"));
    }
    let token = prefix
        .strip_prefix(PREFIX_HEAD)
        .and_then(|rest| rest.strip_suffix(PREFIX_TAIL))
        .ok_or(DbTestError::InvalidName("namespace prefix shape"))?;
    if token.is_empty() {
        return Err(DbTestError::InvalidName("namespace prefix token"));
    }
    let bytes = token.as_bytes();
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(DbTestError::InvalidName("namespace prefix characters"));
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err(DbTestError::InvalidName("namespace prefix boundary"));
    }
    Ok(())
}

/// Quote one SQL identifier by wrapping it in double quotes and doubling any
/// embedded double quote. This is the single identifier quoting helper for the
/// whole template-database path.
pub(crate) fn quote_identifier(name: &str) -> String {
    let mut quoted = String::with_capacity(name.len() + 2);
    quoted.push('"');
    for character in name.chars() {
        if character == '"' {
            quoted.push('"');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}
