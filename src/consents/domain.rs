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
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
}

/// 同意记录在某一时刻的撤销状态，带权威存储的状态版本号（Issue #276）。
///
/// **为什么撤销标记要带版本号**：
/// 撤销和重新授权都是「先写 PostgreSQL，再写 Redis 缓存」。两条链路交错时
/// Redis 的写入顺序可以与数据库的提交顺序相反，迟到的撤销写入会覆盖
/// 重新授权刚刚写下的正确状态，留下与 `revoked_at IS NULL` 相矛盾的陈旧标记。
///
/// 把版本号带上之后，缓存值自己就能回答「我描述的是哪一个 DB 状态」，
/// 条件写就能拒绝任何比缓存中已有结论更旧的写入。
///
/// `version` 由数据库在撤销 / 重新授权的同一条语句内自增，严格单调，
/// 因此比较大小等价于比较「谁描述的 DB 状态更新」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentState {
    /// `true` 表示 `revoked_at IS NOT NULL`。
    pub revoked: bool,
    /// `user_consents.state_version`：每次状态跃迁自增。
    pub version: i64,
}

impl ConsentState {
    pub fn new(revoked: bool, version: i64) -> Self {
        Self { revoked, version }
    }
}

/// 判定已存储的 scope 集合是否覆盖请求的全部 scope。
///
/// 领域规则放在这里而不是下沉成 SQL 条件：scope 覆盖语义属于授权规则，
/// 与存储实现无关，且必须能在不连接数据库的情况下测试。
pub fn scopes_are_covered(stored: &[String], requested: &[String]) -> bool {
    requested.iter().all(|scope| stored.contains(scope))
}

pub fn normalize_scopes(scopes: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;

    scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn merge_scopes(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut combined = Vec::with_capacity(existing.len() + incoming.len());
    combined.extend_from_slice(existing);
    combined.extend_from_slice(incoming);
    normalize_scopes(&combined)
}

#[cfg(test)]
mod tests {
    use super::{AuthorizedApp, ConsentServiceError, ConsentState, scopes_are_covered};

    #[test]
    fn consent_state_versions_are_comparable_across_transitions() {
        // 撤销 → 重新授权 → 再撤销：版本号严格单调，缓存据此判定谁更新
        let revoked = ConsentState::new(true, 2);
        let reauthorized = ConsentState::new(false, 3);
        let revoked_again = ConsentState::new(true, 4);

        assert!(reauthorized.version > revoked.version);
        assert!(revoked_again.version > reauthorized.version);
        // 同一版本号必然描述同一状态，因此相等版本可安全互相覆盖（幂等续期）
        assert_eq!(ConsentState::new(true, 2), revoked);
    }

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
            logo_uri: None,
            client_uri: None,
        })
        .expect("authorized app serializes");
        let object = value.as_object().expect("authorized app object");

        assert_eq!(object.len(), 6);
        assert!(object.contains_key("client_id"));
        assert!(object.contains_key("client_name"));
        assert!(object.contains_key("scopes"));
        assert!(object.contains_key("updated_at"));
        assert!(object.contains_key("logo_uri"));
        assert!(object.contains_key("client_uri"));
        assert_eq!(object["updated_at"], "1970-01-01T00:00:00Z");
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
