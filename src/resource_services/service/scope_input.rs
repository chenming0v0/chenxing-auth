//! 资源服务 scope 声明字段的输入校验。
//!
//! 与 0059 迁移里的 CHECK / UNIQUE 约束一一对应：这里先在业务层拒绝，数据库约束只
//! 作为最后一道防线。不依赖 regex crate，字符集规则直接逐字符判定。

use crate::clients::domain::RESERVED_SCOPES;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::types::ScopeAccess;

pub const MAX_SLUG_LENGTH: usize = 64;
pub const MAX_SCOPE_LENGTH: usize = 128;
pub const MAX_SCOPE_DESCRIPTION_LENGTH: usize = 256;
pub const MAX_CLIENT_ID_LENGTH: usize = 255;

/// 已通过校验的 scope 声明；`scope` 缺省为 `<slug>:access`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDeclaration {
    pub slug: String,
    pub scope: String,
    pub scope_description: String,
    pub scope_access: ScopeAccess,
    pub allowed_client_ids: Vec<String>,
}

impl ScopeDeclaration {
    pub fn validate(
        slug: String,
        scope: Option<String>,
        scope_description: String,
        scope_access: ScopeAccess,
        allowed_client_ids: Vec<String>,
    ) -> Result<Self, ServiceError> {
        validate_slug(&slug)?;
        let scope = scope
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default_scope(&slug));
        validate_scope(&scope)?;
        if scope_description.chars().count() > MAX_SCOPE_DESCRIPTION_LENGTH {
            return Err(ServiceError::InvalidInput("scope_description"));
        }
        validate_allowed_client_ids(&allowed_client_ids)?;
        Ok(Self {
            slug,
            scope,
            scope_description,
            scope_access,
            allowed_client_ids,
        })
    }
}

pub fn default_scope(slug: &str) -> String {
    format!("{slug}:access")
}

/// `^[a-z][a-z0-9_-]{0,63}$`
pub fn validate_slug(value: &str) -> Result<(), ServiceError> {
    if matches_pattern(value, MAX_SLUG_LENGTH, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
    }) {
        Ok(())
    } else {
        Err(ServiceError::InvalidInput("slug"))
    }
}

/// `^[a-z][a-z0-9_.:-]{0,127}$`，且不得与 OIDC 保留 scope 冲突。
pub fn validate_scope(value: &str) -> Result<(), ServiceError> {
    let shape_ok = matches_pattern(value, MAX_SCOPE_LENGTH, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-')
    });
    if !shape_ok || RESERVED_SCOPES.contains(&value) {
        return Err(ServiceError::InvalidInput("scope"));
    }
    Ok(())
}

pub fn validate_allowed_client_ids(values: &[String]) -> Result<(), ServiceError> {
    let all_ok = values
        .iter()
        .all(|value| !value.is_empty() && value.len() <= MAX_CLIENT_ID_LENGTH);
    if all_ok {
        Ok(())
    } else {
        Err(ServiceError::InvalidInput("allowed_client_ids"))
    }
}

fn matches_pattern(value: &str, max_length: usize, tail: impl Fn(char) -> bool) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase() && value.len() <= max_length && chars.all(tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_shape_is_enforced() {
        assert!(validate_slug("termhub").is_ok());
        assert!(validate_slug("a").is_ok());
        assert!(validate_slug("svc_1-2").is_ok());
        assert!(validate_slug(&"a".repeat(64)).is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("1abc").is_err());
        assert!(validate_slug("Abc").is_err());
        assert!(validate_slug("a:b").is_err());
        assert!(validate_slug(&"a".repeat(65)).is_err());
    }

    #[test]
    fn scope_shape_and_reserved_names_are_enforced() {
        assert!(validate_scope("termhub:access").is_ok());
        assert!(validate_scope("svc.read").is_ok());
        assert!(validate_scope(&"a".repeat(128)).is_ok());
        assert!(validate_scope("").is_err());
        assert!(validate_scope("Svc").is_err());
        assert!(validate_scope("svc read").is_err());
        assert!(validate_scope(&"a".repeat(129)).is_err());
        for reserved in ["openid", "profile", "email", "offline_access"] {
            assert!(validate_scope(reserved).is_err(), "{reserved}");
        }
    }

    #[test]
    fn scope_defaults_to_slug_access() {
        let declaration = ScopeDeclaration::validate(
            "termhub".to_owned(),
            None,
            String::new(),
            ScopeAccess::Restricted,
            Vec::new(),
        )
        .expect("valid");
        assert_eq!(declaration.scope, "termhub:access");
        let explicit = ScopeDeclaration::validate(
            "termhub".to_owned(),
            Some("terminal.read".to_owned()),
            String::new(),
            ScopeAccess::Public,
            vec!["app-1".to_owned()],
        )
        .expect("valid");
        assert_eq!(explicit.scope, "terminal.read");
    }

    #[test]
    fn description_and_client_ids_are_bounded() {
        assert!(
            ScopeDeclaration::validate(
                "svc".to_owned(),
                None,
                "x".repeat(257),
                ScopeAccess::Restricted,
                Vec::new(),
            )
            .is_err()
        );
        assert!(validate_allowed_client_ids(&[String::new()]).is_err());
        assert!(validate_allowed_client_ids(&["x".repeat(256)]).is_err());
        assert!(validate_allowed_client_ids(&["x".repeat(255), "y".to_owned()]).is_ok());
    }
}
