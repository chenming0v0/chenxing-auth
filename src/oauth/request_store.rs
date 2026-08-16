use redis::{AsyncCommands, Script};
use thiserror::Error;

use super::consent::PendingAuthorization;
use super::request_store_scripts::{
    PENDING_CAPACITY_SCRIPT, PENDING_REPLACE_SCRIPT, PENDING_TAKE_IF_MATCHES_SCRIPT,
    PENDING_TAKE_SCRIPT,
};
#[path = "request_store_keys.rs"]
mod keys;
use crate::{
    redis_client::RedisClient,
    redis_keyspace::RedisKeyspace,
    settings::{SecurityLimitsSetting, SettingsService, SettingsServiceError},
};

/// Pending request defaults retained for standalone store users and compatibility tests.
pub const PENDING_REQUEST_TTL_SECONDS: u64 = 600;
pub const MAX_PENDING_REQUESTS_PER_CLIENT: u64 = 20;
pub const MAX_PENDING_REQUESTS_GLOBAL: u64 = 1_000;

#[derive(Clone)]
pub struct AuthorizationRequestStore {
    client: RedisClient,
    settings: Option<SettingsService>,
    keyspace: RedisKeyspace,
}

#[derive(Debug, Error)]
pub enum AuthorizationRequestStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("authorization request serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("pending authorization request capacity exceeded")]
    CapacityExceeded,
    #[error("security limits setting operation failed: {0}")]
    Settings(#[from] SettingsServiceError),
}

#[derive(Debug)]
pub struct ConsumedPendingAuthorization {
    pub request: PendingAuthorization,
    pub remaining_ttl_ms: u64,
}

impl AuthorizationRequestStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            settings: None,
            keyspace: RedisKeyspace::default(),
        }
    }

    pub fn with_keyspace(client: impl Into<RedisClient>, keyspace: RedisKeyspace) -> Self {
        Self {
            client: client.into(),
            settings: None,
            keyspace,
        }
    }

    pub fn new_with_settings(client: impl Into<RedisClient>, settings: SettingsService) -> Self {
        Self {
            client: client.into(),
            settings: Some(settings),
            keyspace: RedisKeyspace::default(),
        }
    }

    pub fn new_with_settings_and_keyspace(
        client: impl Into<RedisClient>,
        settings: SettingsService,
        keyspace: RedisKeyspace,
    ) -> Self {
        Self {
            client: client.into(),
            settings: Some(settings),
            keyspace,
        }
    }

    pub async fn save(
        &self,
        request: &PendingAuthorization,
    ) -> Result<(), AuthorizationRequestStoreError> {
        if self.save_limited(request).await? {
            Ok(())
        } else {
            Err(AuthorizationRequestStoreError::CapacityExceeded)
        }
    }

    pub async fn save_limited(
        &self,
        request: &PendingAuthorization,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.save_limited_with_limits(request, &limits).await
    }

    pub async fn save_limited_with_limits(
        &self,
        request: &PendingAuthorization,
        limits: &SecurityLimitsSetting,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        self.save_limited_with_limits_and_ttl(request, limits, None)
            .await
    }

    /// Restore a consumed pending request with its remaining lifetime.
    /// Shared client/global index TTLs are never shortened to this value.
    pub async fn save_limited_with_ttl(
        &self,
        request: &PendingAuthorization,
        remaining_ttl_ms: u64,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.save_limited_with_limits_and_ttl(request, &limits, Some(remaining_ttl_ms))
            .await
    }

    pub async fn save_limited_with_limits_and_ttl(
        &self,
        request: &PendingAuthorization,
        limits: &SecurityLimitsSetting,
        remaining_ttl_ms: Option<u64>,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let payload = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: i64 = Script::new(PENDING_CAPACITY_SCRIPT)
            .key(self.key(&request.request_id))
            .key(self.client_capacity_key(&request.client_id))
            .key(self.global_capacity_key())
            .key(self.client_index_key(&request.client_id))
            .key(self.global_index_key())
            .key(self.global_expiry_key())
            .arg(payload)
            .arg(limits.pending_request_ttl_seconds)
            .arg(limits.max_pending_requests_per_client)
            .arg(limits.max_pending_requests_global)
            .arg(&request.client_id)
            .arg(&request.request_id)
            .arg(self.request_prefix())
            .arg(self.client_index_prefix())
            .arg(self.client_capacity_prefix())
            // 0 = use configured pending_request_ttl_seconds. Shared index
            // TTLs are max(existing, this); see expire_at_least in Lua.
            .arg(remaining_ttl_ms.unwrap_or_default())
            .invoke_async(&mut connection)
            .await?;
        Ok(result == 1)
    }

    pub async fn take(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.take_with_limits(request_id, &limits).await
    }

    async fn take_with_limits(
        &self,
        request_id: &str,
        limits: &SecurityLimitsSetting,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<(String, i64)> = Script::new(PENDING_TAKE_SCRIPT)
            .key(self.key(request_id))
            .key(self.global_index_key())
            .key(self.global_capacity_key())
            .key(self.global_expiry_key())
            .arg(request_id)
            .arg(limits.pending_request_ttl_seconds)
            .arg(self.client_index_prefix())
            .arg(self.client_capacity_prefix())
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|(payload, _)| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    pub async fn take_if_matches(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.take_if_matches_with_limits(request_id, request, &limits)
            .await
    }

    pub(crate) async fn take_if_matches_with_ttl(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
    ) -> Result<Option<ConsumedPendingAuthorization>, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.take_if_matches_with_limits_and_ttl(request_id, request, &limits)
            .await
    }

    async fn take_if_matches_with_limits(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
        limits: &SecurityLimitsSetting,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<(String, i64)> = Script::new(PENDING_TAKE_IF_MATCHES_SCRIPT)
            .key(self.key(request_id))
            .key(self.global_index_key())
            .key(self.global_capacity_key())
            .key(self.global_expiry_key())
            .arg(expected)
            .arg(request_id)
            .arg(limits.pending_request_ttl_seconds)
            .arg(self.client_index_prefix())
            .arg(self.client_capacity_prefix())
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|(payload, _)| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    async fn take_if_matches_with_limits_and_ttl(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
        limits: &SecurityLimitsSetting,
    ) -> Result<Option<ConsumedPendingAuthorization>, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<(String, i64)> = Script::new(PENDING_TAKE_IF_MATCHES_SCRIPT)
            .key(self.key(request_id))
            .key(self.global_index_key())
            .key(self.global_capacity_key())
            .key(self.global_expiry_key())
            .arg(expected)
            .arg(request_id)
            .arg(limits.pending_request_ttl_seconds)
            .arg(self.client_index_prefix())
            .arg(self.client_capacity_prefix())
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|(payload, remaining_ttl_ms)| {
                Ok::<ConsumedPendingAuthorization, serde_json::Error>(
                    ConsumedPendingAuthorization {
                        request: serde_json::from_str(&payload)?,
                        remaining_ttl_ms: remaining_ttl_ms.max(0) as u64,
                    },
                )
            })
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    pub async fn replace_if_matches(
        &self,
        request_id: &str,
        expected: &PendingAuthorization,
        replacement: &PendingAuthorization,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let limits = self.current_limits().await?;
        self.replace_if_matches_with_limits(request_id, expected, replacement, &limits)
            .await
    }

    async fn replace_if_matches_with_limits(
        &self,
        request_id: &str,
        expected: &PendingAuthorization,
        replacement: &PendingAuthorization,
        limits: &SecurityLimitsSetting,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(expected)?;
        let replacement = serde_json::to_string(replacement)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let replaced: i64 = Script::new(PENDING_REPLACE_SCRIPT)
            .key(self.key(request_id))
            .key(self.global_index_key())
            .key(self.global_capacity_key())
            .key(self.global_expiry_key())
            .arg(expected)
            .arg(replacement)
            .arg(request_id)
            .arg(limits.pending_request_ttl_seconds)
            .arg(limits.max_pending_requests_per_client)
            .arg(limits.max_pending_requests_global)
            .arg(self.client_index_prefix())
            .arg(self.client_capacity_prefix())
            .invoke_async(&mut connection)
            .await?;
        Ok(replaced == 1)
    }

    pub async fn find(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(request_id)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    async fn current_limits(
        &self,
    ) -> Result<SecurityLimitsSetting, AuthorizationRequestStoreError> {
        match &self.settings {
            Some(settings) => Ok(settings.security_limits().await?),
            None => Ok(SecurityLimitsSetting::default()),
        }
    }
}
