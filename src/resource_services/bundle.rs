//! Account Provider v1 令牌包（创建与刷新同形状）。
//!
//! 令牌是消费方必须**可逆**持有的密文内容，因此这里的令牌类型不自动
//! `Debug` / `Serialize`：明文只能经 [`SecretString::expose`] 等价路径显式取得，
//! 且仅在加密落库时使用。校验时可以把 issuer、uid、binding、grant 与调用方期望
//! 绑定，创建与刷新走不同的显式方法。

use std::fmt;

use serde_json::{Map, Value};
use uuid::Uuid;

use super::error::ProtocolError;
use super::scalar::{
    Issuer, UtcTime, parse_json_limited, parse_seconds, parse_utc, required, required_string,
};
use super::secret::SecretString;
use super::snapshot::AccountSnapshot;

pub const PROTOCOL_NAME: &str = "account-provider/v1";
pub const ACCOUNT_READ_SCOPE: &str = "account:read";
pub const TOKEN_TYPE_BEARER: &str = "Bearer";
pub const ACCESS_TOKEN_PREFIX: &str = "cxap_at_";
pub const REFRESH_TOKEN_PREFIX: &str = "cxap_rt_";

/// 协议基线：access token 有效期上限。大于它说明响应不可能合法，且会让后续
/// 时间计算溢出。
pub const MAX_EXPIRES_IN_SECONDS: u64 = 900;

const MAX_TOKEN_BYTES: usize = 512;

/// 带协议前缀的 access token。`Debug` 脱敏，且不实现 `Serialize`。
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        valid_prefixed_token(
            value,
            ACCESS_TOKEN_PREFIX,
            ProtocolError::InvalidAccessToken,
        )
        .map(Self)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted access token>")
    }
}

/// 带协议前缀的 refresh token。`Debug` 脱敏，且不实现 `Serialize`。
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        valid_prefixed_token(
            value,
            REFRESH_TOKEN_PREFIX,
            ProtocolError::InvalidRefreshToken,
        )
        .map(Self)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted refresh token>")
    }
}

fn valid_prefixed_token(
    value: &str,
    prefix: &'static str,
    error: ProtocolError,
) -> Result<String, ProtocolError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(error);
    };
    // 只要求带正确前缀、非空、无空白/控制字符；不把令牌擅自限制成某一种随机编码。
    if suffix.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(error);
    }
    Ok(value.to_owned())
}

/// 刷新时必须保持不变的绑定身份。由调用方从本地已持久化的 grant 读出。
#[derive(Debug, Clone, Copy)]
pub struct RefreshBinding<'a> {
    pub grant_id: Uuid,
    pub uid: &'a str,
    pub grant_expires_at: UtcTime,
}

/// 已校验的令牌包。创建与刷新响应同形状。
#[derive(Clone)]
pub struct TokenBundle {
    pub protocol: String,
    pub issuer: Issuer,
    pub grant_id: Uuid,
    pub client_binding_id: Uuid,
    pub uid: String,
    pub scope: String,
    pub token_type: String,
    pub access_token: AccessToken,
    pub expires_in: u64,
    pub refresh_token: RefreshToken,
    pub refresh_expires_at: UtcTime,
    pub grant_expires_at: UtcTime,
    pub snapshot: AccountSnapshot,
}

impl TokenBundle {
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
        let grant_id = parse_uuid(map, "grant_id")?;
        let client_binding_id = parse_uuid(map, "client_binding_id")?;
        let uid = required_string(map, "uid", 1, 255)?;
        let scope = required_string(map, "scope", 1, 64)?;
        if scope != ACCOUNT_READ_SCOPE {
            return Err(ProtocolError::ScopeMismatch);
        }
        let token_type = required_string(map, "token_type", 1, 16)?;
        if token_type != TOKEN_TYPE_BEARER {
            return Err(ProtocolError::TokenTypeMismatch);
        }
        let access_token =
            AccessToken::parse(&required_string(map, "access_token", 1, MAX_TOKEN_BYTES)?)?;
        let expires_in = parse_seconds(required(map, "expires_in")?, "expires_in")?;
        if expires_in > MAX_EXPIRES_IN_SECONDS {
            return Err(ProtocolError::InvalidValue("expires_in"));
        }
        let refresh_token =
            RefreshToken::parse(&required_string(map, "refresh_token", 1, MAX_TOKEN_BYTES)?)?;
        let refresh_expires_at =
            parse_utc(required(map, "refresh_expires_at")?, "refresh_expires_at")?;
        let grant_expires_at = parse_utc(required(map, "grant_expires_at")?, "grant_expires_at")?;
        if refresh_expires_at > grant_expires_at {
            return Err(ProtocolError::RefreshExpiryExceedsGrant);
        }
        let snapshot = AccountSnapshot::from_value(required(map, "snapshot")?)?;
        Ok(Self {
            protocol,
            issuer,
            grant_id,
            client_binding_id,
            uid,
            scope,
            token_type,
            access_token,
            expires_in,
            refresh_token,
            refresh_expires_at,
            grant_expires_at,
            snapshot,
        })
    }

    /// 创建响应校验：绑定到调用方生成的 `client_binding_id` 与配置 issuer。
    pub fn validate_create(
        &self,
        issuer: &Issuer,
        client_binding_id: Uuid,
    ) -> Result<(), ProtocolError> {
        self.validate_common(issuer, client_binding_id)
    }

    /// 刷新响应校验：额外要求 grant 身份、uid 与绝对期限不变。
    pub fn validate_refresh(
        &self,
        issuer: &Issuer,
        client_binding_id: Uuid,
        binding: &RefreshBinding<'_>,
    ) -> Result<(), ProtocolError> {
        self.validate_common(issuer, client_binding_id)?;
        if self.grant_id != binding.grant_id {
            return Err(ProtocolError::GrantMismatch);
        }
        if self.uid != binding.uid {
            return Err(ProtocolError::UidMismatch);
        }
        if self.grant_expires_at != binding.grant_expires_at {
            return Err(ProtocolError::GrantExpiryMismatch);
        }
        Ok(())
    }

    fn validate_common(
        &self,
        issuer: &Issuer,
        client_binding_id: Uuid,
    ) -> Result<(), ProtocolError> {
        if self.issuer.as_str() != issuer.as_str() {
            return Err(ProtocolError::IssuerMismatch);
        }
        if self.client_binding_id != client_binding_id {
            return Err(ProtocolError::BindingMismatch);
        }
        if self.scope != ACCOUNT_READ_SCOPE {
            return Err(ProtocolError::ScopeMismatch);
        }
        if self.snapshot.uid != self.uid {
            return Err(ProtocolError::SnapshotUidMismatch);
        }
        if self.snapshot.issuer.as_str() != self.issuer.as_str() {
            return Err(ProtocolError::SnapshotIssuerMismatch);
        }
        Ok(())
    }

    /// 显式导出完整令牌包明文，**只**用于可逆加密落库。
    ///
    /// 这是唯一会把令牌写入字符串的接口；返回值是 [`SecretString`]，不会因
    /// `Debug` 或 `Serialize` 泄漏明文。持久化层应立刻交给
    /// `crypto::encrypt_secret`，不要把它写入普通日志或普通字符串字段。
    pub fn to_storage_plaintext(&self) -> SecretString {
        let value = serde_json::json!({
            "protocol": self.protocol,
            "issuer": self.issuer.as_str(),
            "grant_id": self.grant_id.to_string(),
            "client_binding_id": self.client_binding_id.to_string(),
            "uid": self.uid,
            "scope": self.scope,
            "token_type": self.token_type,
            "access_token": self.access_token.expose(),
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token.expose(),
            "refresh_expires_at": self.refresh_expires_at.to_rfc3339(),
            "grant_expires_at": self.grant_expires_at.to_rfc3339(),
            "snapshot": self.snapshot.to_value(),
        });
        SecretString::new(value.to_string())
    }
}

impl fmt::Debug for TokenBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenBundle")
            .field("protocol", &self.protocol)
            .field("issuer", &self.issuer)
            .field("grant_id", &self.grant_id)
            .field("client_binding_id", &self.client_binding_id)
            .field("uid", &self.uid)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("access_token", &self.access_token)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("grant_expires_at", &self.grant_expires_at)
            .finish_non_exhaustive()
    }
}

fn parse_uuid(map: &Map<String, Value>, field: &'static str) -> Result<Uuid, ProtocolError> {
    let text = map
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::UnexpectedType(field))?;
    Uuid::parse_str(text).map_err(|_| ProtocolError::InvalidValue(field))
}
