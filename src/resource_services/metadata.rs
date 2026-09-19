//! `GET /.well-known/account-provider` 元数据的严格解析。
//!
//! 元数据只描述门户如何展示凭据输入与提供方能力，**不**包含任何令牌、密钥或账号
//! 数据。未知顶层字段按前向兼容忽略；`credentials` 固定 3 个描述键。issuer 与
//! 调用方配置的 origin 的绑定由客户端负责（见 `client.rs`）。

use serde_json::Value;

use super::bundle::PROTOCOL_NAME;
use super::error::ProtocolError;
use super::scalar::{Issuer, bounded_string, parse_json_limited, required, required_string};

pub const ACCOUNT_READ_CAPABILITY: &str = "account:read";
const MAX_CAPABILITIES: usize = 16;

/// 提供方定义的凭据输入标签。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLabels {
    pub identifier_label: String,
    pub secret_label: String,
    pub identifier_sensitive: bool,
}

/// 已校验的公开元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub protocol: String,
    pub issuer: Issuer,
    pub capabilities: Vec<String>,
    pub credentials: CredentialLabels,
}

impl ProviderMetadata {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_value(&parse_json_limited(bytes)?)
    }

    pub fn from_value(value: &Value) -> Result<Self, ProtocolError> {
        let map = value.as_object().ok_or(ProtocolError::NotAnObject)?;
        let protocol = required_string(map, "protocol", 1, 64)?;
        if protocol != PROTOCOL_NAME {
            return Err(ProtocolError::ProtocolMismatch);
        }
        let issuer = Issuer::parse(&required_string(map, "issuer", 1, 255)?)?;
        let capabilities = parse_capabilities(required(map, "capabilities")?)?;
        let credentials = parse_credentials(required(map, "credentials")?)?;
        Ok(Self {
            protocol,
            issuer,
            capabilities,
            credentials,
        })
    }

    pub fn supports_account_read(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability == ACCOUNT_READ_CAPABILITY)
    }
}

fn parse_capabilities(value: &Value) -> Result<Vec<String>, ProtocolError> {
    let entries = value
        .as_array()
        .ok_or(ProtocolError::UnexpectedType("capabilities"))?;
    if entries.len() > MAX_CAPABILITIES {
        return Err(ProtocolError::InvalidValue("capabilities"));
    }
    let mut capabilities = Vec::with_capacity(entries.len());
    for entry in entries {
        let capability = bounded_string(entry, "capabilities[]", 1, 64)?;
        if capabilities.contains(&capability) {
            return Err(ProtocolError::InvalidValue("capabilities"));
        }
        capabilities.push(capability);
    }
    if !capabilities
        .iter()
        .any(|capability| capability == ACCOUNT_READ_CAPABILITY)
    {
        return Err(ProtocolError::InvalidValue("capabilities"));
    }
    Ok(capabilities)
}

fn parse_credentials(value: &Value) -> Result<CredentialLabels, ProtocolError> {
    let map = value
        .as_object()
        .ok_or(ProtocolError::UnexpectedType("credentials"))?;
    // `credentials` 是**固定 3 个描述键**的对象：多一个键就拒绝，而不是读三项后
    // 假装对象固定。
    if map.len() != 3 {
        return Err(ProtocolError::InvalidValue("credentials"));
    }
    let identifier_label = bounded_string(
        required(map, "identifier_label")?,
        "identifier_label",
        1,
        128,
    )?;
    let secret_label = bounded_string(required(map, "secret_label")?, "secret_label", 1, 128)?;
    let identifier_sensitive = required(map, "identifier_sensitive")?
        .as_bool()
        .ok_or(ProtocolError::UnexpectedType("identifier_sensitive"))?;
    Ok(CredentialLabels {
        identifier_label,
        secret_label,
        identifier_sensitive,
    })
}
