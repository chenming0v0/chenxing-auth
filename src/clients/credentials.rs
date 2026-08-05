//! Client 凭据签发与校验（Issue #66 / #92）。

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use serde::{Deserialize, Deserializer, de::Error as _};
use uuid::Uuid;

use super::{
    domain::{ClientAuthMethod, ClientRegistrationInput},
    repository::ClientCredential,
    service::ClientServiceError,
};
use crate::users::credentials::verify_password;

/// Client 注册请求。
///
/// 在 domain::ClientRegistrationInput 基础上增加 `auth_method`，
/// 用于控制是否签发 secret（凭据签发策略），而不是注册本身的业务约束。
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    #[serde(flatten)]
    pub registration: ClientRegistrationInput,
    /// 认证方式：
    /// - `client_secret_basic` / `client_secret_post` 为机密客户端，签发 secret；
    /// - `none` 为公开客户端（SPA / 移动端），不签发 secret，依赖授权端点强制 PKCE S256。
    ///
    /// 默认 `client_secret_basic`（与现有行为保持兼容）。
    /// 无效值（如 `"jwt"`）被 serde 拒绝，axum 返回 422 Unprocessable Entity。
    #[serde(
        default = "default_auth_method",
        deserialize_with = "deserialize_auth_method"
    )]
    pub auth_method: ClientAuthMethod,
}

fn default_auth_method() -> ClientAuthMethod {
    ClientAuthMethod::Basic
}

fn deserialize_auth_method<'de, D>(deserializer: D) -> Result<ClientAuthMethod, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    ClientAuthMethod::parse(&s).ok_or_else(|| {
        D::Error::custom(format!(
            "unsupported auth_method: '{}', expected 'client_secret_basic', 'client_secret_post', or 'none'",
            s
        ))
    })
}

impl From<ClientRegistrationInput> for ClientRegistrationRequest {
    fn from(registration: ClientRegistrationInput) -> Self {
        Self {
            registration,
            auth_method: default_auth_method(),
        }
    }
}

/// 生成新的 Client Secret 明文及其 Argon2 哈希（Issue #92 抽取共享逻辑）。
pub fn generate_client_secret() -> Result<(String, String), ClientServiceError> {
    let client_secret = format!("cxs_{}", Uuid::new_v4().simple());
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(client_secret.as_bytes(), &salt)
        .map_err(|_| ClientServiceError::SecretHash)?
        .to_string();
    Ok((client_secret, hash))
}

/// 根据 `auth_method` 决定是否签发 secret。
///
/// - 机密客户端（`basic` / `post`）：生成 UUID secret + Argon2 哈希。
/// - 公开客户端（`none`）：不生成 secret，返回 `None`。
pub fn issue_client_credential(
    auth_method: ClientAuthMethod,
) -> Result<(ClientCredential, Option<String>), ClientServiceError> {
    match auth_method {
        ClientAuthMethod::Basic => {
            let (plaintext, hash) = generate_client_secret()?;
            Ok((ClientCredential::SecretBasic(hash), Some(plaintext)))
        }
        ClientAuthMethod::Post => {
            let (plaintext, hash) = generate_client_secret()?;
            Ok((ClientCredential::SecretPost(hash), Some(plaintext)))
        }
        ClientAuthMethod::None => Ok((ClientCredential::Public, None)),
    }
}

pub fn verify_client_secret(secret: &str, encoded_hash: &str) -> bool {
    verify_password(secret, encoded_hash)
}

/// 校验 Client 凭据是否匹配（Issue #63 #66 合并重构）。
///
/// 返回 `true` 当且仅当：
/// 1. 认证方式与数据库存储一致；
/// 2. 公开客户端（`auth_method = none`）且请求未携带 secret；
/// 3. 或机密客户端且 secret 通过 Argon2 哈希校验。
///
/// 任何不匹配（auth_method 不符、secret 存在性矛盾、哈希校验失败）都返回 `false`，
/// 避免在认证失败路径上泄露 Client 配置细节（时序攻击防护）。
pub fn credentials_match(
    auth_method: ClientAuthMethod,
    client_secret: Option<&str>,
    stored_hash: Option<&str>,
) -> bool {
    match (auth_method, client_secret, stored_hash) {
        // 公开客户端：请求不带 secret、数据库不存 hash。
        // 若数据库有 hash 遗留（如配置迁移错误），拒绝认证（fail closed）。
        (ClientAuthMethod::None, None, None) => true,
        // 机密客户端：请求带 secret、数据库存 hash，且 Argon2 校验通过。
        (ClientAuthMethod::Basic | ClientAuthMethod::Post, Some(secret), Some(hash)) => {
            verify_client_secret(secret, hash)
        }
        // 其他组合均为配置错误或攻击尝试，拒绝。
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造注册请求 JSON，可选附加 auth_method 字段
    fn registration_json(auth_method: Option<&str>) -> String {
        let base = r#""client_name":"Test","redirect_uris":["https://example.com/cb"],"scopes":["openid"]"#;
        match auth_method {
            Some(method) => format!(r#"{{{base},"auth_method":"{method}"}}"#),
            None => format!("{{{base}}}"),
        }
    }

    #[test]
    fn client_registration_request_defaults_to_basic_auth() {
        // 未显式指定 auth_method 时保持既有行为：机密客户端 + Basic
        let request: ClientRegistrationRequest =
            serde_json::from_str(&registration_json(None)).expect("default auth method");
        assert_eq!(request.auth_method, ClientAuthMethod::Basic);
    }

    #[test]
    fn client_registration_request_accepts_public_auth_method() {
        // Issue #66：公开客户端注册必须能通过 HTTP 请求体表达
        let request: ClientRegistrationRequest =
            serde_json::from_str(&registration_json(Some("none"))).expect("public auth method");
        assert_eq!(request.auth_method, ClientAuthMethod::None);
    }

    #[test]
    fn client_registration_request_accepts_post_auth_method() {
        let request: ClientRegistrationRequest =
            serde_json::from_str(&registration_json(Some("client_secret_post")))
                .expect("post auth method");
        assert_eq!(request.auth_method, ClientAuthMethod::Post);
    }

    #[test]
    fn client_registration_request_rejects_unsupported_auth_method() {
        // 无效 auth_method 在反序列化阶段被拒绝，不会落到默认值上
        assert!(
            serde_json::from_str::<ClientRegistrationRequest>(&registration_json(Some("jwt")))
                .is_err()
        );
    }

    #[test]
    fn client_registration_input_converts_with_basic_default() {
        // 既有调用方传 ClientRegistrationInput 时行为不变
        let request: ClientRegistrationRequest = ClientRegistrationInput {
            client_name: "Legacy".to_owned(),
            redirect_uris: vec!["https://legacy.example/cb".to_owned()],
            scopes: vec!["openid".to_owned()],
        }
        .into();
        assert_eq!(request.auth_method, ClientAuthMethod::Basic);
    }

    #[test]
    fn issue_confidential_credential_generates_secret_and_hash() {
        let (credential, plaintext) =
            issue_client_credential(ClientAuthMethod::Basic).expect("basic credential");
        assert!(matches!(credential, ClientCredential::SecretBasic(_)));
        assert!(plaintext.is_some());
        assert!(plaintext.as_ref().unwrap().starts_with("cxs_"));
    }

    #[test]
    fn issue_public_credential_has_no_secret() {
        let (credential, plaintext) =
            issue_client_credential(ClientAuthMethod::None).expect("public credential");
        assert!(matches!(credential, ClientCredential::Public));
        assert!(plaintext.is_none());
    }

    #[test]
    fn credentials_match_accepts_public_client_without_secret() {
        // 公开客户端：请求不带 secret、数据库不存 hash（Issue #66）
        assert!(credentials_match(ClientAuthMethod::None, None, None));
    }

    #[test]
    fn credentials_match_rejects_public_client_with_leaked_hash() {
        // 若公开客户端在数据库里遗留了 hash（配置迁移错误），拒绝认证（fail closed）
        assert!(!credentials_match(
            ClientAuthMethod::None,
            None,
            Some("leaked-hash")
        ));
    }

    #[test]
    fn credentials_match_rejects_mismatched_secret_presence() {
        // 机密客户端请求带 secret，但数据库没 hash（或反之），都拒绝
        assert!(!credentials_match(
            ClientAuthMethod::Basic,
            Some("secret"),
            None
        ));
        assert!(!credentials_match(
            ClientAuthMethod::Basic,
            None,
            Some("hash")
        ));
    }

    #[test]
    fn generated_client_secrets_are_unique() {
        let (secret1, _) = generate_client_secret().unwrap();
        let (secret2, _) = generate_client_secret().unwrap();
        assert_ne!(secret1, secret2);
    }
}
