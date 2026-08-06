//! 同意领域模型（领域层）
//!
//! 只包含纯数据结构、错误类型和不依赖存储的领域规则。
//! 本模块不引用 `sqlx` 查询、Redis 客户端或 Axum 请求类型。

use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;

/// 同意用例的错误类型。
///
/// 按边界区分（AGENTS.md）：`Database` 是基础设施故障（应重试/503），
/// `ClientNotFound` 是业务信号（客户端配置问题），二者不可混淆。
#[derive(Debug, Error)]
pub enum ConsentServiceError {
    /// 数据库操作失败
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),

    /// 保存同意记录时对应的 OAuth Client 不存在
    #[error("OAuth client not found")]
    ClientNotFound,
}

/// 用户已授权应用的对外视图。
///
/// 只包含可安全返回给用户的字段：不含 client_secret、redirect_uris 等
/// 客户端配置或凭据材料。
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizedApp {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub updated_at: OffsetDateTime,
}

/// 判定已存储的 scope 集合是否覆盖请求的全部 scope。
///
/// 领域规则放在这里而不是下沉成 SQL 条件：scope 覆盖语义属于授权规则，
/// 与存储实现无关，且必须能在不连接数据库的情况下测试。
pub fn scopes_are_covered(stored: &[String], requested: &[String]) -> bool {
    requested.iter().all(|scope| stored.contains(scope))
}

#[cfg(test)]
mod tests {
    use super::{AuthorizedApp, ConsentServiceError, scopes_are_covered};

    #[test]
    fn client_not_found_error_does_not_leak_internal_details() {
        let message = ConsentServiceError::ClientNotFound.to_string();

        assert_eq!(message, "OAuth client not found");
        // 错误信息面向调用方，不得暴露 SQL 语句或表结构
        assert!(!message.contains("INSERT"));
        assert!(!message.contains("user_consents"));
        assert!(!message.contains("oauth_clients"));
    }

    #[test]
    fn sqlx_error_converts_into_database_variant() {
        let error = ConsentServiceError::from(crate::sqlx::Error::RowNotFound);

        // 基础设施错误必须落在 Database 变体上，不能被误判成业务信号 ClientNotFound
        assert!(matches!(error, ConsentServiceError::Database(_)));
        assert!(error.to_string().starts_with("database operation failed:"));
    }

    #[test]
    fn authorized_app_response_contains_only_non_sensitive_fields() {
        let value = serde_json::to_value(AuthorizedApp {
            client_id: "cx_test".to_owned(),
            client_name: "Example App".to_owned(),
            scopes: vec!["openid".to_owned()],
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("authorized app serializes");
        let object = value.as_object().expect("authorized app object");

        assert_eq!(object.len(), 4);
        assert!(object.contains_key("client_id"));
        assert!(object.contains_key("client_name"));
        assert!(object.contains_key("scopes"));
        assert!(object.contains_key("updated_at"));
        assert!(!object.contains_key("client_secret"));
        assert!(!object.contains_key("redirect_uris"));
    }

    #[test]
    fn scope_coverage_requires_every_requested_scope() {
        let stored = vec!["openid".to_owned(), "profile".to_owned()];

        assert!(scopes_are_covered(&stored, &["openid".to_owned()]));
        assert!(scopes_are_covered(
            &stored,
            &["openid".to_owned(), "profile".to_owned()]
        ));
        // 请求了未授权的 scope：必须整体拒绝，不能部分放行
        assert!(!scopes_are_covered(&stored, &["email".to_owned()]));
        assert!(!scopes_are_covered(
            &stored,
            &["openid".to_owned(), "email".to_owned()]
        ));
    }

    #[test]
    fn empty_request_is_covered_by_any_stored_scope_set() {
        // 空请求不要求任何权限，恒为覆盖；这保持与 `Iterator::all` 的语义一致
        assert!(scopes_are_covered(&[], &[]));
        assert!(scopes_are_covered(&["openid".to_owned()], &[]));
    }
}
