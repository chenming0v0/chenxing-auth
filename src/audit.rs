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
//! 有三档策略，按「业务写入是否还能被审计结果改写」来选：
//!
//! - **同事务**（最强）：审计 INSERT 与业务写入共享一个数据库事务，通过
//!   [`repository::insert_with`] 传入业务事务。审计失败连带回滚业务写入，因此
//!   不存在「业务已提交、审计丢失」的中间态。代价是审计故障会让业务写入不可用，
//!   所以只用于一生只发生一次、丢失即不可补的路径 —— 目前是 Owner 引导
//!   （Issue #304，见 `users::repository::bootstrap_owner`）。
//! - **阻断式**（[`AuditService::record_blocking`]）：业务已提交但凭据尚未交出，
//!   审计失败则不交凭据。
//! - **best-effort**（[`AuditService::record_best_effort`]）：业务结果已经确定且
//!   不可逆，审计失败不改写它。
//!
//! 后两档共用一个前提：业务写入与审计写入不在同一事务，因此审计不能决定一个
//! 已经完成的业务写入是否发生。所有调用点都必须先确定业务结果，再按操作性质
//! 选择策略：
//!
//! - [`AuditService::record_blocking`] 用于凭据签发或消费路径。调用方只能在审计
//!   成功后返回凭据；失败时返回通用错误，并对仍可逆的状态执行补偿。Client
//!   secret 创建/轮换即使业务写入已经提交，也不会把 secret 返回给调用方，且
//!   `audit.block_on_failure` 日志保留人工补账所需的上下文。
//! - [`AuditService::record_best_effort`] 用于普通状态变更和已经确定的拒绝路径。
//!   这些操作的成功或拒绝结果不因审计数据库暂时不可用而被改写，也不尝试为了
//!   审计失败回滚不可逆的业务状态。失败会统一记录
//!   `audit.best_effort_failure`，包含 actor、action、resource 和元数据里的
//!   `reason`，供告警与人工补录。
//!
//! 这套顺序避免了两种错误：把已经生效的状态变更伪装成 500，诱导调用方重复执行；
//! 或者在凭据没有可追溯审计记录时仍把凭据交给调用方。阻断式路径仍存在一个提交
//! 窗口（业务已提交、审计未落库），彻底消除它的办法就是升级到同事务策略；是否
//! 升级取决于该路径能否接受「审计不可用时业务也不可用」。

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::sleep;

use crate::clock::{Clock, SharedClock, SystemClock};

pub mod classification;
mod redaction;
pub mod repository;
#[cfg(test)]
mod unit_tests;

pub use classification::{SecurityEventCategory, SecurityEventSeverity, classify};
pub(crate) use redaction::redact_metadata;

pub(crate) const AUDIT_ARCHIVE_BATCH_SIZE: i32 = 1_000;
const AUDIT_WRITE_MAX_ATTEMPTS: u32 = 3;
const AUDIT_RETRY_DELAY: Duration = Duration::from_millis(25);

#[derive(Clone)]
pub struct AuditService {
    pool: crate::sqlx::PgPool,
    clock: SharedClock,
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
        Self {
            pool,
            clock: SharedClock::system(),
        }
    }

    /// 注入共享时钟（`AppState` 构造时调用）。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// 落库前重新盖上审计时刻。
    ///
    /// `AuditEvent::new` 在构造时先盖一次进程默认时钟，是为了让直接构造事件的
    /// 调用点不必显式取时间；但服务是这个时间戳的权威来源，因此这里用注入的
    /// 共享时钟覆盖它。两者在生产中都是墙钟、差值在微秒级；在测试里则保证
    /// 落库时刻与其它生命周期判定看到同一个固定时钟。
    pub async fn record(&self, mut event: AuditEvent) -> Result<(), AuditError> {
        event.created_at = self.clock.now();
        self.record_in_place(&mut event).await
    }

    /// 按可重试性落库一个事件，脱敏后的事件留在调用方手里。
    ///
    /// 借用而不接管所有权，是为了让失败留痕能复用同一份已脱敏的事件字段，
    /// 而不必在每个成功路径上都先克隆一遍 actor / action / resource。
    async fn record_in_place(&self, event: &mut AuditEvent) -> Result<(), AuditError> {
        event.redact_metadata_in_place();
        if let Err(error) = event.validate() {
            tracing::error!(error = %error, action = %event.action, "rejected audit event");
            return Err(error);
        }

        let mut attempt = 1;
        loop {
            match repository::insert_with(&self.pool, event).await {
                Ok(()) => return Ok(()),
                Err(error) if !is_retryable_database_error(&error) => {
                    tracing::error!(
                        event = "audit.persistence_failed",
                        action = %event.action,
                        attempts = attempt,
                        retryable = false,
                        error = %error,
                        "audit event could not be persisted; error is not safe to retry"
                    );
                    return Err(error);
                }
                Err(error) if attempt >= AUDIT_WRITE_MAX_ATTEMPTS => {
                    tracing::error!(
                        event = "audit.persistence_failed",
                        action = %event.action,
                        attempts = attempt,
                        retryable = true,
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

    /// 落库失败时把事件的可检索字段原样打进结构化日志。
    ///
    /// `reason` 取自事件元数据：拒绝路径（授权不足、CSRF 失败、Owner 守卫拒绝）
    /// 的判定依据只存在于元数据里，丢掉它等于让「审计没写进去的那次拒绝」在日志里
    /// 无法与其他拒绝区分。元数据在 `record_in_place` 里已经过脱敏，因此这里打印
    /// 的是与入库内容一致的安全视图，不会把敏感输入带进日志。
    async fn record_with_failure_event(
        &self,
        mut event: AuditEvent,
        failure_event: &'static str,
    ) -> Result<(), AuditError> {
        match self.record_in_place(&mut event).await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::error!(
                    event = failure_event,
                    action = %event.action,
                    actor_type = %event.actor_type,
                    actor_id = ?event.actor_id,
                    resource_type = %event.resource_type,
                    resource_id = ?event.resource_id,
                    reason = ?event.metadata.get("reason"),
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
        repository::query_filtered(
            &self.pool,
            action,
            resource_type,
            limit.clamp(1, 100),
            offset.max(0),
        )
        .await
    }

    pub async fn query_security_events(
        &self,
        actor_user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SecurityEvent>, i64), crate::sqlx::Error> {
        repository::query_security_events(
            &self.pool,
            actor_user_id,
            limit.clamp(1, 100),
            offset.max(0),
        )
        .await
    }

    /// 查询单个安全事件详情；事件不存在或不属于该用户时返回 `None`。
    pub async fn query_security_event(
        &self,
        actor_user_id: i64,
        event_id: i64,
    ) -> Result<Option<SecurityEventDetail>, crate::sqlx::Error> {
        repository::query_security_event(&self.pool, actor_user_id, event_id).await
    }

    pub async fn count(&self) -> Result<i64, crate::sqlx::Error> {
        repository::count_filtered(&self.pool, None, None).await
    }

    pub async fn archive_expired(&self, retention_days: i32) -> Result<i64, crate::sqlx::Error> {
        repository::archive_expired(&self.pool, retention_days).await
    }
}

/// Retrying an audit insert is safe only when its outcome is known before a
/// successful insert could have been committed. A pool acquisition timeout
/// never sends the statement; PostgreSQL's serialization and deadlock errors
/// abort the failed statement/transaction. Network and protocol errors remain
/// single-shot because the server may already have committed the insert.
fn is_retryable_database_error(error: &AuditError) -> bool {
    match error {
        AuditError::Database(crate::sqlx::Error::PoolTimedOut) => true,
        AuditError::Database(error) => error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .is_some_and(|code| code == "40001" || code == "40P01"),
        _ => false,
    }
}

/// 用户可见的审计事件视图（摘要 / 详情 / 请求上下文白名单提取）。
///
/// 拆分到独立模块是为了让 `audit.rs` 保持以 [`AuditEvent`] 写入路径与
/// [`AuditService`] 为主线的职责边界（Issue #308）。
mod security_views;
pub use security_views::{SecurityEvent, SecurityEventClient, SecurityEventDetail};
pub(crate) use security_views::{security_event_request_context, with_request_context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub metadata: Map<String, Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl AuditEvent {
    /// 构造审计事件。
    ///
    /// `created_at` 在这里只是一个构造期占位：真正落库的时刻由
    /// [`AuditService::record`] 用注入的共享时钟重新盖上。保留这次墙钟读取，
    /// 是为了让不经过服务的调用点（序列化、诊断输出）也拿到合理的时间。
    pub fn new(
        actor_type: String,
        actor_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        metadata: Value,
    ) -> Self {
        Self::new_at(
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            metadata,
            SystemClock.now(),
        )
    }

    /// 以显式时刻构造审计事件。
    #[allow(clippy::too_many_arguments)]
    pub fn new_at(
        actor_type: String,
        actor_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        metadata: Value,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: 0,
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            metadata: redact_metadata(metadata),
            created_at: now,
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
            None,
        )
    }

    /// 构造认证失败事件的非凭据上下文。
    ///
    /// 用户名和邮箱可能属于个人数据，不能原样写入审计。规范化后的标识符只用于
    /// 生成跨事件稳定的 SHA-256 引用；来源地址必须已经由可信代理解析器取得，且
    /// 这里再次 canonicalize，避免审计落入带端口或非标准 IPv6 表示。
    #[allow(clippy::too_many_arguments)]
    pub fn authentication_failure(
        action: String,
        actor_type: String,
        actor_id: Option<String>,
        resource_type: String,
        resource_id: Option<String>,
        reason: impl Into<String>,
        attempted_identifier: Option<&str>,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
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
        if let Some(user_agent) = user_agent.filter(|value| !value.is_empty()) {
            metadata.insert(
                "user_agent".to_owned(),
                Value::String(user_agent.to_owned()),
            );
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
///
/// 这里的 `trim().to_ascii_lowercase()` 是**兜底**，不是邮箱规范化。调用方应当
/// 传入已经规范化的标识符（邮箱走 `EmailAddress::canonical()`，用户名走
/// `validate_username`），因为对 Unicode 域名而言，本函数的 ASCII 小写与真正的
/// IDNA 匹配值不同——同一个账号会因此得到两个不同的 `account_ref`，按账号检索
/// 审计就漏事件（Issue #302）。
///
/// 之所以仍保留兜底而不改成只接受规范化输入：登录标识符解析失败的路径也需要
/// 一个可写入的引用，而那种输入本身就不存在"规范形态"。
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
