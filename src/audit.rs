//! Durable security audit boundary.
//!
//! `audit_events` is an append-only record of security-relevant decisions. The
//! database owns retention and archival policy; application code must not turn
//! a failed write into a successful security mutation.
//!
//! # 两种审计策略：阻断式 vs Best-effort
//!
//! ## 凭据签发路径——阻断式审计
//!
//! `client_create` 和 `client_secret_rotate` 遵循**阻断式审计**策略：
//! 先写审计，审计成功后才将 secret 返回给调用者。若审计写入失败（含重试），
//! 处理器返回 500，调用者收不到任何凭据。
//!
//! 这意味着仍存在一个窄窗口——底层 DB 变更（client 行/secret hash）已提交，
//! 但 `audit_events` 写入失败。与"静默签发"相比，这种取舍更安全：
//!
//! - **攻击者拿不到可用凭据**：500 响应中不含 secret，无法直接利用。
//! - **可观测、可追溯**：处理器在 `tracing::error!` 里记录了 `client_id`、
//!   `actor_id` 和操作类型，运维可根据日志人工补录审计记录或撤销 client。
//! - **可重试**：调用方收到 500 后可通过管理 API 查询 client 状态再决策；
//!   相比之下，静默签发的凭据一旦落到攻击者手里无法撤回。
//!
//! 若需完全消除此窗口，须将 client DB 写入与 `audit_events` 写入放在同一
//! 数据库事务中（事务回滚 = 凭据未签发），这需要修改 `ClientService` 签名，
//! 留待后续迭代。
//!
//! ## 拒绝路径——Best-effort 审计
//!
//! 已认证用户触发 admin 授权失败（权限不足或 CSRF 校验失败）时，
//! 写入 `admin_authorization_denied` 事件遵循 **best-effort** 策略：
//!
//! - 请求本来就要被拒绝（403/400）；审计写入失败**不改变**这一安全决策。
//! - 若把审计错误升级为 500，反而向探测者泄露"这次探测触发了服务端异常"，
//!   且"拒绝"动作本身不签发任何凭据，没有需要阻断的对象。
//! - 写入失败时通过 `tracing::error!(event = "audit.authorization_denial_unrecorded", ...)`
//!   保留结构化上下文，供运维告警和人工补录。
//!
//! 两种策略的核心判断依据：**安全决策的方向**。
//! 阻断式 = "不审计则不给凭据"；best-effort = "已拒绝，审计失败不改变结果"。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::sleep;

pub mod repository;

const AUDIT_WRITE_MAX_ATTEMPTS: u32 = 3;
const AUDIT_RETRY_DELAY: Duration = Duration::from_millis(25);

#[derive(Clone)]
pub struct AuditService {
    pool: crate::sqlx::PgPool,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit actor type is invalid")]
    InvalidActorType,
    #[error("audit actor id is invalid")]
    InvalidActorId,
    #[error("failed to persist audit event")]
    Database(#[source] crate::sqlx::Error),
}

impl AuditService {
    pub fn new(pool: crate::sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        if let Err(error) = event.validate() {
            tracing::error!(error = %error, action = %event.action, "rejected audit event");
            return Err(error);
        }

        let mut attempt = 1;
        loop {
            match repository::insert(&self.pool, &event).await {
                Ok(()) => return Ok(()),
                Err(error) if attempt >= AUDIT_WRITE_MAX_ATTEMPTS => {
                    tracing::error!(
                        event = "audit.persistence_failed",
                        action = %event.action,
                        attempts = attempt,
                        error = %error,
                        "audit event could not be persisted after retries"
                    );
                    return Err(error);
                }
                Err(error) => {
                    tracing::warn!(
                        event = "audit.persistence_retry",
                        action = %event.action,
                        attempt,
                        error = %error,
                        "retrying audit event persistence"
                    );
                    sleep(AUDIT_RETRY_DELAY * attempt).await;
                    attempt += 1;
                }
            }
        }
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<AuditEvent>, crate::sqlx::Error> {
        repository::list(&self.pool, limit.clamp(1, 200)).await
    }

    pub async fn query(
        &self,
        action: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AuditEvent>, i64), crate::sqlx::Error> {
        let total = repository::count_filtered(&self.pool, action, resource_type).await?;
        let events = repository::list_filtered(
            &self.pool,
            action,
            resource_type,
            limit.clamp(1, 100),
            offset.max(0),
        )
        .await?;
        Ok((events, total))
    }

    pub async fn count(&self) -> Result<i64, crate::sqlx::Error> {
        repository::count_filtered(&self.pool, None, None).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub metadata: Map<String, Value>,
    pub created_at: OffsetDateTime,
}

impl AuditEvent {
    pub fn new(
        actor_type: String,
        actor_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        metadata: Value,
    ) -> Self {
        Self {
            id: 0,
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            metadata: redact_metadata(metadata),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn security_failure(
        action: String,
        actor_type: String,
        actor_id: Option<String>,
        resource_type: String,
        resource_id: Option<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            serde_json::json!({"result": "failure", "reason": reason.into()}),
        )
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        if self.actor_type.is_empty()
            || self.actor_type.len() > 64
            || !self
                .actor_type
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AuditError::InvalidActorType);
        }
        if self
            .actor_id
            .as_deref()
            .is_some_and(|actor_id| actor_id.parse::<i64>().is_err())
        {
            return Err(AuditError::InvalidActorId);
        }
        Ok(())
    }
}

pub(crate) fn redact_metadata(metadata: Value) -> Map<String, Value> {
    let Value::Object(metadata) = metadata else {
        return Map::new();
    };
    match redact_value(Value::Object(metadata)) {
        Some(Value::Object(metadata)) => metadata,
        _ => Map::new(),
    }
}

fn redact_value(value: Value) -> Option<Value> {
    match value {
        Value::Object(object) => Some(Value::Object(
            object
                .into_iter()
                .filter_map(|(key, value)| {
                    if is_sensitive_key(&key) {
                        return None;
                    }
                    Some((key, redact_value(value)?))
                })
                .collect(),
        )),
        Value::Array(values) => Some(Value::Array(
            values.into_iter().filter_map(redact_value).collect(),
        )),
        value => Some(value),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    [
        b"password".as_slice(),
        b"clientsecret".as_slice(),
        b"accesstoken".as_slice(),
        b"refreshtoken".as_slice(),
        b"authorizationcode".as_slice(),
        b"codeverifier".as_slice(),
        b"totpsecret".as_slice(),
        b"secret".as_slice(),
        b"token".as_slice(),
        b"credential".as_slice(),
        b"privatekey".as_slice(),
        b"apikey".as_slice(),
    ]
    .iter()
    .any(|marker| {
        normalized
            .windows(marker.len())
            .any(|window| window == *marker)
    })
}
