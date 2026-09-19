//! 消费方持久化行类型。不含令牌明文。

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::users::domain::UserId;

pub const OPERATION_CREATE: &str = "create";
pub const OPERATION_REFRESH: &str = "refresh";
pub const OPERATION_REVOKE: &str = "revoke";

pub const STATUS_LEASED: &str = "leased";
pub const STATUS_COMMITTED: &str = "committed";
pub const STATUS_FAILED: &str = "failed";

pub const OPERATION_LEASE: time::Duration = time::Duration::seconds(30);

/// 资源服务 scope 的开放范围。数据库以 TEXT 存储（`restricted` / `public`）。
///
/// - `Restricted`：只有 `allowed_client_ids` 中列出的应用可申请该 scope；
/// - `Public`：本站所有已注册应用均可申请。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScopeAccess {
    #[default]
    Restricted,
    Public,
}

impl ScopeAccess {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted",
            Self::Public => "public",
        }
    }
}

impl fmt::Display for ScopeAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// 数据库 TEXT 与枚举之间的映射；CHECK 约束保证列值只会是这两种。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown scope access value")]
pub struct UnknownScopeAccess;

impl FromStr for ScopeAccess {
    type Err = UnknownScopeAccess;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "restricted" => Ok(Self::Restricted),
            "public" => Ok(Self::Public),
            _ => Err(UnknownScopeAccess),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ciphertext: String,
    pub identifier_label: String,
    pub secret_label: String,
    pub identifier_sensitive: bool,
    /// 该资源服务声明的 OAuth scope；应用申请此 scope 即表示要访问该服务的用户资源。
    pub scope: String,
    pub scope_description: String,
    pub scope_access: ScopeAccess,
    /// `scope_access == Restricted` 时允许申请的 `oauth_clients.client_id` 列表。
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct BindingRow {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub user_id: UserId,
    pub uid: String,
    pub issuer: String,
    pub grant_id: Option<Uuid>,
    pub grant_expires_at: Option<OffsetDateTime>,
    pub generation: i64,
    pub tombstoned_at: Option<OffsetDateTime>,
    pub token_bundle_ciphertext: Option<String>,
    pub snapshot_json: Value,
    pub access_expires_at: Option<OffsetDateTime>,
    pub refresh_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl BindingRow {
    pub fn is_live(&self) -> bool {
        self.tombstoned_at.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct OperationRow {
    pub idempotency_key: Uuid,
    pub provider_id: Uuid,
    pub binding_id: Uuid,
    pub user_id: UserId,
    pub operation_type: String,
    pub status: String,
    pub lease_until: Option<OffsetDateTime>,
    pub request_fingerprint: String,
    pub provider_revision: i64,
    pub created_at: OffsetDateTime,
    pub committed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub binding_id: Uuid,
    pub user_id: UserId,
    pub attempts: i32,
    pub available_at: OffsetDateTime,
    pub processed_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
}

/// 提供方身份（issuer / client_id）在有未完成绑定、操作或撤销任务时不可改。
pub fn provider_identity_locked(
    live_bindings: i64,
    leased_operations: i64,
    pending_outbox: i64,
) -> bool {
    live_bindings > 0 || leased_operations > 0 || pending_outbox > 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingOperation {
    ReplayCommitted,
    ReplayInFlight,
    ReclaimExpiredLease,
    FingerprintConflict,
    Failed,
}

/// 已存在操作行的分类。指纹不同一律 fail-closed，不重放、不回收。
pub fn classify_existing_operation(
    row: &OperationRow,
    fingerprint: &str,
    now: OffsetDateTime,
) -> ExistingOperation {
    if row.request_fingerprint != fingerprint {
        return ExistingOperation::FingerprintConflict;
    }
    match row.status.as_str() {
        STATUS_COMMITTED => ExistingOperation::ReplayCommitted,
        STATUS_FAILED => ExistingOperation::Failed,
        STATUS_LEASED => {
            if row.lease_until.is_some_and(|until| until > now) {
                ExistingOperation::ReplayInFlight
            } else {
                ExistingOperation::ReclaimExpiredLease
            }
        }
        _ => ExistingOperation::FingerprintConflict,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExistingOperation, OPERATION_CREATE, OperationRow, STATUS_COMMITTED, STATUS_FAILED,
        STATUS_LEASED, ScopeAccess, classify_existing_operation, provider_identity_locked,
    };
    use time::OffsetDateTime;

    #[test]
    fn scope_access_round_trips_through_text() {
        for access in [ScopeAccess::Restricted, ScopeAccess::Public] {
            assert_eq!(access.to_string().parse::<ScopeAccess>(), Ok(access));
        }
        assert!("owner".parse::<ScopeAccess>().is_err());
        assert_eq!(ScopeAccess::default(), ScopeAccess::Restricted);
        assert_eq!(
            serde_json::to_string(&ScopeAccess::Public).expect("serialize"),
            "\"public\""
        );
    }

    #[test]
    fn operation_types_are_distinct() {
        assert_ne!(super::OPERATION_CREATE, super::OPERATION_REFRESH);
        assert_ne!(super::OPERATION_CREATE, super::OPERATION_REVOKE);
        assert_ne!(super::OPERATION_REFRESH, super::OPERATION_REVOKE);
    }

    #[test]
    fn identity_is_locked_when_any_in_flight_work_exists() {
        assert!(!provider_identity_locked(0, 0, 0));
        assert!(provider_identity_locked(1, 0, 0));
        assert!(provider_identity_locked(0, 1, 0));
        assert!(provider_identity_locked(0, 0, 1));
    }

    #[test]
    fn existing_operation_classification_is_fail_closed() {
        let now = OffsetDateTime::now_utc();
        let mut row = OperationRow {
            idempotency_key: uuid::Uuid::nil(),
            provider_id: uuid::Uuid::nil(),
            binding_id: uuid::Uuid::nil(),
            user_id: 1,
            operation_type: OPERATION_CREATE.to_owned(),
            status: STATUS_LEASED.to_owned(),
            lease_until: Some(now + time::Duration::seconds(10)),
            request_fingerprint: "abc".to_owned(),
            provider_revision: 1,
            created_at: now,
            committed_at: None,
        };
        assert_eq!(
            classify_existing_operation(&row, "abc", now),
            ExistingOperation::ReplayInFlight
        );
        row.lease_until = Some(now - time::Duration::seconds(1));
        assert_eq!(
            classify_existing_operation(&row, "abc", now),
            ExistingOperation::ReclaimExpiredLease
        );
        row.status = STATUS_COMMITTED.to_owned();
        assert_eq!(
            classify_existing_operation(&row, "abc", now),
            ExistingOperation::ReplayCommitted
        );
        assert_eq!(
            classify_existing_operation(&row, "other", now),
            ExistingOperation::FingerprintConflict
        );
        row.status = STATUS_FAILED.to_owned();
        assert_eq!(
            classify_existing_operation(&row, "abc", now),
            ExistingOperation::Failed
        );
    }
}
