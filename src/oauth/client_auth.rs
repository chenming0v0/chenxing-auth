use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::fmt;
use thiserror::Error;

use crate::clients::domain::ClientAuthMethod;

/// client_id 请求侧长度上限（字节，Issue #353）。
///
/// 服务端签发的 client_id 恒为 `cx_` + 32 位 hex（35 字节）；上限取 128
/// 为未来格式留出余量，同时把进入 DB 绑定与后续处理的值压到常量级。
pub const MAX_CLIENT_ID_LENGTH: usize = 128;

/// client_secret 请求侧长度上限（字节，Issue #353）。
///
/// 服务端签发的 secret 恒为 `cxs_` + 32 位 hex（36 字节）。Argon2 对输入
/// 长度的开销是线性的，超长 secret 会把「每请求一次 Argon2」的阻塞池占用
/// 放大数倍（源限流只能缓解不能消除），因此在进入校验前必须按字节封顶。
pub const MAX_CLIENT_SECRET_LENGTH: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_method: ClientAuthMethod,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientCredentialError {
    #[error("client authentication methods must not be combined")]
    MultipleMethods,
    #[error("client credentials are missing")]
    Missing,
    #[error("client credentials are invalid")]
    Invalid,
    #[error("client credentials exceed the length limit")]
    TooLong,
}

/// 校验解析出的凭据长度是否在上限内。
///
/// 用字节而非字符数：决定资源消耗（Argon2 输入、DB 绑定参数）的是字节数，
/// 且本系统签发的凭据均为 ASCII，两者对合法值等价。
fn credentials_within_limits(client_id: &str, client_secret: Option<&str>) -> bool {
    client_id.len() <= MAX_CLIENT_ID_LENGTH
        && client_secret.is_none_or(|secret| secret.len() <= MAX_CLIENT_SECRET_LENGTH)
}

pub fn resolve_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<ClientCredentials, ClientCredentialError> {
    let form_has_credentials = form_client_id.is_some() || form_client_secret.is_some();
    let basic = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, encoded) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("Basic").then_some(encoded)
        });

    if basic.is_some() && form_has_credentials {
        return Err(ClientCredentialError::MultipleMethods);
    }
    // 先解析凭据，再在唯一的出口统一过长度闸：Basic 与 form 两条路径共享
    // 同一道校验，任何超长输入都不会流入 Argon2 或 DB 绑定（Issue #353）。
    let credentials = if let Some(encoded) = basic {
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| ClientCredentialError::Invalid)?;
        let value = String::from_utf8(decoded).map_err(|_| ClientCredentialError::Invalid)?;
        let (client_id, client_secret) = value
            .split_once(':')
            .ok_or(ClientCredentialError::Invalid)?;
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(ClientCredentialError::Invalid);
        }
        ClientCredentials {
            client_id: client_id.to_owned(),
            client_secret: Some(client_secret.to_owned()),
            auth_method: ClientAuthMethod::Basic,
        }
    } else {
        match (form_client_id, form_client_secret) {
            (Some(client_id), Some(client_secret)) if !client_id.is_empty() => ClientCredentials {
                client_id: client_id.to_owned(),
                client_secret: Some(client_secret.to_owned()),
                auth_method: ClientAuthMethod::Post,
            },
            (Some(client_id), None) if !client_id.is_empty() => ClientCredentials {
                client_id: client_id.to_owned(),
                client_secret: None,
                auth_method: ClientAuthMethod::None,
            },
            _ => return Err(ClientCredentialError::Missing),
        }
    };
    if !credentials_within_limits(&credentials.client_id, credentials.client_secret.as_deref()) {
        return Err(ClientCredentialError::TooLong);
    }
    Ok(credentials)
}
