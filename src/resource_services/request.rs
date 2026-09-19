//! Account Provider v1 三个会话变更请求体（创建 / 刷新 / 撤销）。
//!
//! `credentials` 只用于一次只读校验：本模块**不**提供任何把原始凭据序列化、
//! 持久化或打印的接口，`Debug` 也只输出 `<redacted>`。创建用的
//! `client_binding_id` 由消费方生成且永不复用。

use std::fmt;

use uuid::Uuid;

use super::bundle::RefreshToken;
use super::error::ProtocolError;
use super::secret::SecretString;

pub const MAX_CREDENTIAL_BYTES: usize = 255;

/// 门户采集到的凭据对。字段私有，只能经访问器交给 HTTP 请求构造函数。
#[derive(Clone)]
pub struct Credentials {
    identifier: SecretString,
    secret: SecretString,
}

impl Credentials {
    pub fn new(
        identifier: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let identifier = SecretString::new(identifier);
        let secret = SecretString::new(secret);
        if identifier.byte_len() == 0
            || identifier.byte_len() > MAX_CREDENTIAL_BYTES
            || secret.byte_len() == 0
            || secret.byte_len() > MAX_CREDENTIAL_BYTES
        {
            return Err(ProtocolError::InvalidCredentials);
        }
        Ok(Self { identifier, secret })
    }

    pub fn identifier(&self) -> &SecretString {
        &self.identifier
    }

    pub fn secret(&self) -> &SecretString {
        &self.secret
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credentials { <redacted> }")
    }
}

/// 创建绑定请求。`client_binding_id` 必须随机且永不复用。
#[derive(Clone)]
pub struct CreateLinkSessionRequest {
    client_binding_id: Uuid,
    credentials: Credentials,
}

impl CreateLinkSessionRequest {
    pub fn new(
        client_binding_id: Uuid,
        identifier: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            client_binding_id,
            credentials: Credentials::new(identifier, secret)?,
        })
    }

    /// 生成新的随机 `client_binding_id`。丢失创建响应时**不要**用新引用盲目重试，
    /// 应先对同一引用发幂等 revoke，再用全新引用重连（protocol.md 第 5 节）。
    pub fn with_random_binding(
        identifier: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        Self::new(Uuid::new_v4(), identifier, secret)
    }

    pub fn client_binding_id(&self) -> Uuid {
        self.client_binding_id
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
}

impl fmt::Debug for CreateLinkSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateLinkSessionRequest")
            .field("client_binding_id", &self.client_binding_id)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// 刷新请求。`refresh_token` 来自上一次成功响应，轮换后旧值立即失效。
#[derive(Clone)]
pub struct RefreshLinkSessionRequest {
    client_binding_id: Uuid,
    refresh_token: RefreshToken,
}

impl RefreshLinkSessionRequest {
    pub fn new(client_binding_id: Uuid, refresh_token: RefreshToken) -> Self {
        Self {
            client_binding_id,
            refresh_token,
        }
    }

    pub fn client_binding_id(&self) -> Uuid {
        self.client_binding_id
    }

    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }
}

impl fmt::Debug for RefreshLinkSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshLinkSessionRequest")
            .field("client_binding_id", &self.client_binding_id)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// 撤销请求。幂等。
#[derive(Debug, Clone, Copy)]
pub struct RevokeLinkSessionRequest {
    client_binding_id: Uuid,
}

impl RevokeLinkSessionRequest {
    pub fn new(client_binding_id: Uuid) -> Self {
        Self { client_binding_id }
    }

    pub fn client_binding_id(&self) -> Uuid {
        self.client_binding_id
    }
}
