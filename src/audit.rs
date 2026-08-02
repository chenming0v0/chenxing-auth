use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;

pub mod repository;

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
        if let Err(error) = repository::insert(&self.pool, &event).await {
            tracing::error!(error = %error, action = %event.action, "failed to persist audit event");
            return Err(error);
        }
        Ok(())
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
