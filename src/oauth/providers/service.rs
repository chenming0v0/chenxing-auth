//! provider 配置的读写与外部身份落地。
//!
//! 与外部 IdP 的协议交互（授权 URL、授权码兑换、UserInfo）在
//! [`super::external_flow`]：那边是本服务作为客户端对外发起请求，信任边界和
//! OAuth-only 信任模型（Issue #296）的说明集中在那个模块。

use super::{
    claims::ExternalUser,
    domain::{ProviderInput, ProviderRecord, ProviderSummary, ProviderValidationError},
    endpoint_policy::{EndpointPolicy, validate_endpoint_url},
    http_client::build_provider_http_client,
    repository::{self, CreateIdentityError},
    secrets::{SecretError, SecretManager},
};
use crate::users::domain::{UserId, UserStatus};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use std::fmt;
use thiserror::Error;

#[derive(Clone)]
pub struct ExternalOAuthService {
    pool: crate::sqlx::PgPool,
    secrets: SecretManager,
    http: Client,
    /// 出网边界策略：决定回环/明文例外是否放行（Issue #343）。
    policy: EndpointPolicy,
}

#[derive(Debug, Error)]
pub enum ExternalOAuthError {
    #[error("provider input is invalid: {0}")]
    Validation(#[from] ProviderValidationError),
    #[error("provider secret operation failed: {0}")]
    Secret(#[from] SecretError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("provider was not found")]
    NotFound,
    #[error("provider is disabled")]
    Disabled,
    #[error("provider secret is not configured")]
    MissingSecret,
    #[error("external provider request failed")]
    RemoteRequest,
    #[error("external provider returned invalid user information")]
    InvalidUserInfo,
    #[error("external email is not verified")]
    EmailNotVerified,
    #[error("external email is already registered")]
    EmailAlreadyRegistered,
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required")]
    OwnerBootstrapRequired,
}

/// 外部 IdP 的令牌响应里本服务实际使用的部分。
///
/// **信任模型（Issue #296）**：自定义 provider 是 OAuth 2.0 + UserInfo，不是 OIDC
/// 依赖方。本服务不解析、不验证、不消费 `id_token`；身份事实只来自用 access token
/// 经 TLS 取回的 UserInfo 响应。因此这个结构里没有 `id_token` 字段——不是遗漏，
/// 是刻意不保存：保存一个从未被验证的 JWT，只会让调用方误以为它可以当身份断言用。
///
/// 要建立 OIDC 身份断言边界（`iss`、`aud`、`exp`、`iat`、`nonce`、`kid` 与算法
/// 白名单），需要 provider 侧的 issuer/JWKS/算法策略配置和签名验证实现，这不在
/// 当前 provider 模型内。在那之前，产品、API、UI 和文档一律只声明 OAuth 2.0。
#[derive(Clone)]
pub struct ExternalToken {
    pub access_token: String,
    pub token_type: Option<String>,
}

impl fmt::Debug for ExternalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalToken")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl ExternalOAuthService {
    pub fn new(
        pool: crate::sqlx::PgPool,
        secrets: SecretManager,
        policy: EndpointPolicy,
    ) -> Result<Self, ExternalOAuthError> {
        // 出网边界（禁用系统代理、解析筛查、禁重定向、超时）全部固定在
        // `http_client` 里，调用点不参与配置，回归测试可以拿到同一份客户端。
        let http =
            build_provider_http_client(policy).map_err(|_| ExternalOAuthError::RemoteRequest)?;
        Ok(Self {
            pool,
            secrets,
            http,
            policy,
        })
    }

    pub async fn list(&self) -> Result<Vec<ProviderSummary>, ExternalOAuthError> {
        Ok(repository::list_providers(&self.pool)
            .await?
            .into_iter()
            .map(|provider| provider.summary())
            .collect())
    }

    pub async fn find(&self, slug: &str) -> Result<ProviderRecord, ExternalOAuthError> {
        repository::find_by_slug(&self.pool, slug)
            .await?
            .ok_or(ExternalOAuthError::NotFound)
    }

    pub async fn create(
        &self,
        input: ProviderInput,
    ) -> Result<ProviderSummary, ExternalOAuthError> {
        let validated = input.validate(self.policy)?;
        let ciphertext = self.encrypt_secret(validated.client_secret.as_deref())?;
        Ok(
            repository::insert_provider(&self.pool, &validated, ciphertext)
                .await?
                .summary(),
        )
    }

    pub async fn update(
        &self,
        slug: &str,
        input: ProviderInput,
    ) -> Result<bool, ExternalOAuthError> {
        let validated = input.validate(self.policy)?;
        let ciphertext = match validated.client_secret.as_deref() {
            Some(secret) => self.encrypt_secret(Some(secret))?,
            None => self.find(slug).await?.client_secret_ciphertext,
        };
        Ok(repository::update_provider(&self.pool, slug, &validated, ciphertext).await?)
    }

    /// 切换 provider 启用状态。
    ///
    /// 启用是唯一需要额外校验的方向，两条都针对「存量行按旧规则写进来」的情况：
    ///
    /// - `email_verified_claim` 可能是 NULL，这类 provider 一旦启用就会放行未验证
    ///   邮箱（Issue #261）。
    /// - 端点可能是按旧规则（只查 scheme）保存的私网地址，启用后服务端就会向它
    ///   发起请求（Issue #291）。这里拒绝比等到运行时 500 更容易让管理员定位。
    ///
    /// 停用永远允许，否则坏配置会卡在启用状态无法关掉。
    pub async fn set_status(&self, slug: &str, status: &str) -> Result<bool, ExternalOAuthError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        if status == "active" {
            let provider = self.find(slug).await?;
            provider.claim_mapping()?;
            validate_endpoint_url(&provider.authorization_endpoint, self.policy)?;
            validate_endpoint_url(&provider.token_endpoint, self.policy)?;
            validate_endpoint_url(&provider.userinfo_endpoint, self.policy)?;
        }
        Ok(repository::set_status(&self.pool, slug, status).await?)
    }

    pub async fn resolve_user(
        &self,
        provider: &ProviderRecord,
        external: &ExternalUser,
    ) -> Result<UserId, ExternalOAuthError> {
        // 纵深防御（Issue #261）：`ExternalUser` 只能由 `from_claims` 构造，那里已经
        // 拒过未验证邮箱。这里再拦一次，保证任何将来新增的构造路径都不能绕过
        // 「未验证邮箱不得登录、更不得自动建号」这条规则。
        if !external.email_verified {
            return Err(ExternalOAuthError::EmailNotVerified);
        }
        if let Some(identity) =
            repository::find_identity(&self.pool, provider.id, &external.subject).await?
        {
            if UserStatus::parse(&identity.user_status) != Some(UserStatus::Active) {
                return Err(ExternalOAuthError::UserDisabled);
            }
            return Ok(identity.user_id);
        }
        let password_hash =
            unusable_password_hash().map_err(|_| ExternalOAuthError::RemoteRequest)?;
        repository::create_user_with_identity(
            &self.pool,
            provider.id,
            &external.email,
            external.name.as_deref(),
            &external.subject,
            &password_hash,
        )
        .await
        .map_err(|error| match error {
            CreateIdentityError::EmailAlreadyRegistered => {
                ExternalOAuthError::EmailAlreadyRegistered
            }
            CreateIdentityError::UserDisabled => ExternalOAuthError::UserDisabled,
            CreateIdentityError::OwnerBootstrapRequired => {
                ExternalOAuthError::OwnerBootstrapRequired
            }
            CreateIdentityError::Database(error) => ExternalOAuthError::Database(error),
        })
    }

    fn encrypt_secret(&self, secret: Option<&str>) -> Result<Vec<u8>, ExternalOAuthError> {
        secret
            .map(|secret| self.secrets.encrypt(secret))
            .transpose()
            .map(|value| value.unwrap_or_default())
            .map_err(Into::into)
    }

    /// 出网客户端。只对 `providers` 模块内部开放：外部 IdP 请求必须走这一份
    /// 受约束的客户端（禁用系统代理、解析筛查、禁重定向、超时），任何模块外的
    /// 调用点自己建 Client 都会绕过 #291/#294 的出网边界。
    pub(super) fn http(&self) -> &Client {
        &self.http
    }

    /// 出网边界策略。协议交互模块（[`super::external_flow`]）校验端点时必须
    /// 使用与保存/启用时相同的策略，否则回环门控（Issue #343）会被绕过。
    pub(super) fn endpoint_policy(&self) -> EndpointPolicy {
        self.policy
    }

    pub(super) fn decrypt_secret(
        &self,
        provider: &ProviderRecord,
    ) -> Result<String, ExternalOAuthError> {
        if provider.client_secret_ciphertext.is_empty() {
            return Err(ExternalOAuthError::MissingSecret);
        }
        self.secrets
            .decrypt(&provider.client_secret_ciphertext)
            .map_err(Into::into)
    }
}

fn unusable_password_hash() -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(
            URL_SAFE_NO_PAD
                .encode(rand::random::<[u8; 32]>())
                .as_bytes(),
            &salt,
        )
        .map(|hash| hash.to_string())
}
