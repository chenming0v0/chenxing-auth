//! Durable security audit boundary.
//!
//! `audit_events` is an append-only record of security-relevant decisions. The
//! database triggers reject mutation of both the hot and archive tables. The
//! explicit `audit-archive` maintenance command moves events older than
//! `AUDIT_RETENTION_DAYS` in one database transaction; the archive is retained
//! indefinitely and is included in audit queries.
//!
//! The web process never archives or deletes audit rows. Deployments that turn
//! on `AUDIT_ARCHIVE_ENABLED` must schedule one maintenance command separately.
//!
//! # 审计失败策略
//!
//! 业务写入与审计写入目前不是同一事务，因此审计不能决定一个已经完成的业务
//! 写入是否发生。所有调用点都必须先确定业务结果，再按操作性质选择策略：
//!
//! - [`AuditService::record_blocking`] 用于凭据签发或消费路径。调用方只能在审计
//!   成功后返回凭据；失败时返回通用错误，并对仍可逆的状态执行补偿。Client
//!   secret 创建/轮换即使业务写入已经提交，也不会把 secret 返回给调用方，且
//!   `audit.block_on_failure` 日志保留人工补账所需的上下文。
//! - [`AuditService::record_best_effort`] 用于普通状态变更和已经确定的拒绝路径。
//!   这些操作的成功或拒绝结果不因审计数据库暂时不可用而被改写，也不尝试为了
//!   审计失败回滚不可逆的业务状态。失败会统一记录
//!   `audit.best_effort_failure`，包含 actor、action 和 resource，供告警与人工补录。
//!
//! 这套顺序避免了两种错误：把已经生效的状态变更伪装成 500，诱导调用方重复执行；
//! 或者在凭据没有可追溯审计记录时仍把凭据交给调用方。要彻底消除阻断式路径的
//! 提交窗口，仍需把业务写入和 `audit_events` 写入放进同一数据库事务。

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::sleep;

pub mod repository;

pub(crate) const AUDIT_ARCHIVE_BATCH_SIZE: i32 = 1_000;
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

    pub async fn record(&self, mut event: AuditEvent) -> Result<(), AuditError> {
        event.redact_metadata_in_place();
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

    /// Persist an audit event while preserving an already-determined operation result.
    ///
    /// The operation has already committed (or has already been rejected) when this
    /// method is called. A failed audit write is therefore observable through the
    /// structured error log, but it must not turn a real success or denial into a
    /// misleading 500 response.
    pub async fn record_best_effort(&self, event: AuditEvent) {
        let _ = self
            .record_with_failure_event(event, "audit.best_effort_failure")
            .await;
    }

    /// Persist an audit event for a credential path that must not return a credential
    /// when its audit record is unavailable.
    pub async fn record_blocking(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.record_with_failure_event(event, "audit.block_on_failure")
            .await
    }

    async fn record_with_failure_event(
        &self,
        event: AuditEvent,
        failure_event: &'static str,
    ) -> Result<(), AuditError> {
        let action = event.action.clone();
        let actor_type = event.actor_type.clone();
        let actor_id = event.actor_id.clone();
        let resource_type = event.resource_type.clone();
        let resource_id = event.resource_id.clone();
        match self.record(event).await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::error!(
                    event = failure_event,
                    action = %action,
                    actor_type = %actor_type,
                    actor_id = ?actor_id,
                    resource_type = %resource_type,
                    resource_id = ?resource_id,
                    error = %error,
                    "audit event was not persisted"
                );
                Err(error)
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

    pub async fn archive_expired(&self, retention_days: i32) -> Result<i64, crate::sqlx::Error> {
        repository::archive_expired(&self.pool, retention_days).await
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

    pub(crate) fn redact_metadata_in_place(&mut self) {
        let metadata = std::mem::take(&mut self.metadata);
        self.metadata = redact_metadata(Value::Object(metadata));
    }

    pub fn security_failure(
        action: String,
        actor_type: String,
        actor_id: Option<String>,
        resource_type: String,
        resource_id: Option<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::authentication_failure(
            action,
            actor_type,
            actor_id,
            resource_type,
            resource_id,
            reason,
            None,
            None,
        )
    }

    /// 构造认证失败事件的非凭据上下文。
    ///
    /// 用户名和邮箱可能属于个人数据，不能原样写入审计。规范化后的标识符只用于
    /// 生成跨事件稳定的 SHA-256 引用；来源地址必须已经由可信代理解析器取得，且
    /// 这里再次 canonicalize，避免审计落入带端口或非标准 IPv6 表示。
    pub fn authentication_failure(
        action: String,
        actor_type: String,
        actor_id: Option<String>,
        resource_type: String,
        resource_id: Option<String>,
        reason: impl Into<String>,
        attempted_identifier: Option<&str>,
        source_ip: Option<&str>,
    ) -> Self {
        let mut metadata = Map::new();
        metadata.insert("result".to_owned(), Value::String("failure".to_owned()));
        metadata.insert("reason".to_owned(), Value::String(reason.into()));
        if let Some(identifier) = attempted_identifier.filter(|value| !value.is_empty()) {
            metadata.insert(
                "account_ref".to_owned(),
                Value::String(stable_account_reference(identifier)),
            );
        }
        if let Some(source_ip) = source_ip.and_then(canonical_source_ip) {
            metadata.insert("source_ip".to_owned(), Value::String(source_ip));
        }
        Self::new(
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            Value::Object(metadata),
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

/// 返回不包含原始用户名或邮箱的稳定账户引用。
pub fn stable_account_reference(identifier: &str) -> String {
    let normalized = identifier.trim().to_ascii_lowercase();
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(normalized.as_bytes()))
    )
}

fn canonical_source_ip(source_ip: &str) -> Option<String> {
    source_ip.parse::<IpAddr>().ok().map(|ip| ip.to_string())
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
        Value::String(value) if contains_sensitive_assignment(&value) => {
            Some(Value::String("[REDACTED]".to_owned()))
        }
        value => Some(value),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    if SAFE_METADATA_KEYS
        .iter()
        .any(|safe_key| normalized == *safe_key)
    {
        return false;
    }
    SENSITIVE_METADATA_KEYS
        .iter()
        .any(|sensitive_key| normalized == *sensitive_key)
}

fn normalize_key(key: &str) -> String {
    key.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

const SAFE_METADATA_KEYS: &[&str] = &[
    "accountref",
    "passwordconfigured",
    "sourceip",
    "tokencount",
    "tokentype",
    "tokentypehint",
];

// These are complete metadata keys, rather than fragments. In particular, this keeps
// protocol facts such as token_type and password_configured available to audit queries.
const SENSITIVE_METADATA_KEYS: &[&str] = &[
    "accesstoken",
    "accesstokenhash",
    "apikey",
    "apikeyvalue",
    "authorization",
    "authorizationcode",
    "code",
    "codechallenge",
    "codeverifier",
    "cookie",
    "cookievalue",
    "clientsecret",
    "clientsecrethash",
    "credential",
    "credentialid",
    "credentialvalue",
    "credentials",
    "csrf",
    "csrfcookie",
    "csrftoken",
    "idtoken",
    "jwt",
    "jwttoken",
    "nonce",
    "otp",
    "otpcode",
    "otpsecret",
    "password",
    "passwordhash",
    "passwordvalue",
    "privatekey",
    "privatekeypem",
    "refreshtoken",
    "secret",
    "secretvalue",
    "session",
    "sessioncookie",
    "sessionid",
    "sessiontoken",
    "signature",
    "signaturevalue",
    "state",
    "statetoken",
    "token",
    "tokenvalue",
    "totp",
    "totpcode",
    "totpsecret",
];

fn contains_sensitive_assignment(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (equals_index, byte) in bytes.iter().enumerate() {
        if *byte != b'=' {
            continue;
        }

        let mut key_end = equals_index;
        while key_end > 0 && bytes[key_end - 1].is_ascii_whitespace() {
            key_end -= 1;
        }
        let mut key_start = key_end;
        while key_start > 0 && is_embedded_key_byte(bytes[key_start - 1]) {
            key_start -= 1;
        }
        if key_start == key_end {
            continue;
        }
        if let Ok(key) = std::str::from_utf8(&bytes[key_start..key_end])
            && is_sensitive_key(key)
        {
            return true;
        }
    }
    false
}

fn is_embedded_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}
