use std::fmt;

/// Redis key namespace shared by every Redis-backed runtime store.
///
/// The implicit `legacy` mode preserves keys created before `REDIS_NAMESPACE`
/// existed. Explicit namespaces are wrapped in a service-owned prefix so they
/// cannot collide with legacy keys or another deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedisKeyspace(Option<String>);

impl RedisKeyspace {
    pub const ENV_NAME: &'static str = "REDIS_NAMESPACE";

    pub fn new(value: &str) -> Result<Self, RedisKeyspaceError> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("legacy") {
            return Ok(Self::default());
        }
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RedisKeyspaceError);
        }
        Ok(Self(Some(value.to_owned())))
    }

    pub fn key(&self, legacy_key: &str) -> String {
        match &self.0 {
            Some(namespace) => format!("chenxing-auth:{namespace}:{legacy_key}"),
            None => legacy_key.to_owned(),
        }
    }

    pub fn prefix(&self, legacy_prefix: &str) -> String {
        self.key(legacy_prefix)
    }

    pub fn namespace(&self) -> &str {
        self.0.as_deref().unwrap_or("legacy")
    }
}

impl Default for RedisKeyspace {
    fn default() -> Self {
        Self(None)
    }
}

impl fmt::Display for RedisKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.namespace())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Redis namespace must contain 1-64 ASCII letters, digits, '.', '_' or '-'")]
pub struct RedisKeyspaceError;

#[cfg(test)]
mod tests {
    use super::RedisKeyspace;

    #[test]
    fn explicit_namespaces_are_disjoint_and_legacy_is_preserved() {
        let first = RedisKeyspace::new("staging").expect("staging namespace");
        let second = RedisKeyspace::new("production").expect("production namespace");
        let legacy_key = "chenxing:oauth:refresh:token-id";

        assert_ne!(first.key(legacy_key), second.key(legacy_key));
        assert_eq!(RedisKeyspace::default().key(legacy_key), legacy_key);
    }

    #[test]
    fn rejects_values_that_could_escape_the_namespace_segment() {
        for value in ["", " ", "staging:oauth", "staging/prod", "生产"] {
            assert!(RedisKeyspace::new(value).is_err(), "accepted {value:?}");
        }
    }
}
