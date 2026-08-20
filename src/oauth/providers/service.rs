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
    secrets::{SecretContext, SecretError, SecretManager},
};
use crate::{
    audit::{AuditError, AuditEvent},
    users::domain::{UserId, UserStatus},
};
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
    #[error("provider audit operation failed: {0}")]
    Audit(#[from] AuditError),
    #[error(transparent)]
    ManagementActor(#[from] crate::users::ManagementActorValidationError),
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
    #[error("external email is not allowed by the registration policy")]
    EmailNotAllowed,
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required")]
    OwnerBootstrapRequired,
}

#[derive(Debug, Error)]
pub enum ExternalIdentityUnlinkError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("external identity was not found")]
    Missing,
    #[error("external identity is the last usable login credential")]
    LastCredential,
}

#[derive(Debug, Error)]
pub enum ExternalIdentityBindingError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("external identity is already linked")]
    AlreadyOwned,
    #[error("external identity is owned by another user")]
    OwnedByAnotherUser,
    #[error("external identity binding session is no longer current")]
    AuthenticationChanged,
    #[error("external email is not verified")]
    EmailNotVerified,
}

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

    pub async fn list_identities(
        &self,
        user_id: UserId,
    ) -> Result<Vec<repository::LinkedExternalIdentity>, ExternalOAuthError> {
        Ok(repository::list_identities(&self.pool, user_id).await?)
    }

    pub async fn bind_identity(
        &self,
        user_id: UserId,
        expected_session_epoch: i64,
        provider_id: i64,
        external: &ExternalUser,
    ) -> Result<(), ExternalIdentityBindingError> {
        if !external.email_verified {
            return Err(ExternalIdentityBindingError::EmailNotVerified);
        }
        repository::bind_identity(
            &self.pool,
            user_id,
            expected_session_epoch,
            provider_id,
            external,
        )
        .await
        .map_err(|error| match error {
            repository::BindIdentityError::Database(error) => {
                ExternalIdentityBindingError::Database(error)
            }
            repository::BindIdentityError::AlreadyOwned => {
                ExternalIdentityBindingError::AlreadyOwned
            }
            repository::BindIdentityError::OwnedByAnotherUser => {
                ExternalIdentityBindingError::OwnedByAnotherUser
            }
            repository::BindIdentityError::AuthenticationChanged => {
                ExternalIdentityBindingError::AuthenticationChanged
            }
        })
    }

    pub async fn unlink_identity(
        &self,
        user_id: UserId,
        expected_session_epoch: i64,
        provider_slug: &str,
    ) -> Result<repository::UnlinkIdentityOutcome, ExternalIdentityUnlinkError> {
        Ok(
            repository::unlink_identity(&self.pool, user_id, expected_session_epoch, provider_slug)
                .await?,
        )
    }

    pub async fn find(&self, slug: &str) -> Result<ProviderRecord, ExternalOAuthError> {
        repository::find_by_slug(&self.pool, slug)
            .await?
            .ok_or(ExternalOAuthError::NotFound)
    }

    pub async fn create_with_audit(
        &self,
        input: ProviderInput,
        credential: crate::users::ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<ProviderSummary, ExternalOAuthError> {
        let validated = input.validate(self.policy)?;
        let mut transaction = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut transaction,
            credential,
            crate::users::domain::UserPermission::ManageIdentityProviders,
        )
        .await?;
        let mut provider =
            repository::insert_provider(&mut transaction, &validated, Vec::new()).await?;
        let ciphertext = self.encrypt_secret(provider.id, validated.client_secret.as_deref())?;
        if !ciphertext.is_empty() {
            repository::update_client_secret_ciphertext(&mut transaction, provider.id, &ciphertext)
                .await?;
            provider.client_secret_ciphertext = ciphertext;
        }
        crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
        transaction.commit().await?;
        Ok(provider.summary())
    }

    pub async fn update_with_audit(
        &self,
        slug: &str,
        input: ProviderInput,
        credential: crate::users::ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<bool, ExternalOAuthError> {
        let validated = input.validate(self.policy)?;
        let mut transaction = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut transaction,
            credential,
            crate::users::domain::UserPermission::ManageIdentityProviders,
        )
        .await?;
        let provider = repository::lock_by_slug(&mut transaction, slug)
            .await?
            .ok_or(ExternalOAuthError::NotFound)?;
        let ciphertext = match validated.client_secret.as_deref() {
            Some(secret) => self.encrypt_secret(provider.id, Some(secret))?,
            None => provider.client_secret_ciphertext,
        };
        let updated =
            repository::update_provider(&mut transaction, slug, &validated, ciphertext).await?;
        if updated {
            crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(updated)
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
    pub async fn set_status_with_audit(
        &self,
        slug: &str,
        status: &str,
        credential: crate::users::ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<bool, ExternalOAuthError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        let mut transaction = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut transaction,
            credential,
            crate::users::domain::UserPermission::ManageIdentityProviders,
        )
        .await?;
        let provider = repository::lock_by_slug(&mut transaction, slug)
            .await?
            .ok_or(ExternalOAuthError::NotFound)?;
        if status == "active" {
            provider.claim_mapping()?;
            validate_endpoint_url(&provider.authorization_endpoint, self.policy)?;
            validate_endpoint_url(&provider.token_endpoint, self.policy)?;
            validate_endpoint_url(&provider.userinfo_endpoint, self.policy)?;
        }
        let updated = repository::set_status(&mut transaction, slug, status).await?;
        if updated {
            crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(updated)
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
        repository::create_user_with_identity(
            &self.pool,
            provider.id,
            &external.email,
            external.name.as_deref(),
            &external.subject,
            UNUSABLE_PASSWORD_HASH,
        )
        .await
        .map_err(|error| match error {
            CreateIdentityError::EmailAlreadyRegistered => {
                ExternalOAuthError::EmailAlreadyRegistered
            }
            CreateIdentityError::EmailPolicyRejected => ExternalOAuthError::EmailNotAllowed,
            CreateIdentityError::UserDisabled => ExternalOAuthError::UserDisabled,
            CreateIdentityError::OwnerBootstrapRequired => {
                ExternalOAuthError::OwnerBootstrapRequired
            }
            CreateIdentityError::Database(error) => ExternalOAuthError::Database(error),
        })
    }

    fn encrypt_secret(
        &self,
        provider_id: i64,
        secret: Option<&str>,
    ) -> Result<Vec<u8>, ExternalOAuthError> {
        secret
            .map(|secret| {
                self.secrets
                    .encrypt_for(SecretContext::Provider(provider_id), secret)
            })
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
            .decrypt_for(
                SecretContext::Provider(provider.id),
                &provider.client_secret_ciphertext,
            )
            .map_err(Into::into)
    }
}

/// 外部用户「不可用口令」的编译期哈希（Issue #342）。
///
/// 外部 IdP 身份落地时 `users.password_hash` 列不能为空，但这里不需要也不应该有
/// 真实口令：旧实现每次建号现场生成随机 32 字节口令并跑一次完整 Argon2
/// （19 MiB 内存、约 50 ms），口令随即被丢弃，哈希永不参与校验。这个计算发生在
/// 回调 handler 的 async 路径上，直接阻塞 Tokio worker；攻击者轮换 IP 即可让
/// 并发外部登录饱和全部 worker（每次新 IdP subject 触发一次哈希）。
///
/// 因此改用编译期常量：格式合法、原像不可知的 PHC 串。结构与
/// `users::credentials::FALLBACK_DUMMY_PASSWORD_HASH` 相同——argon2id、v=19、
/// m=19456、t=2、p=1（与 `Argon2::default()` 一致），salt 与 digest 全零，没有
/// 口令能哈希出全零摘要，任何校验恒定失败。这正是「不可用」的语义：即使将来
/// `password_login_enabled` 被意外置真，外部用户也无法用口令登录。建号路径因此
/// 零计算成本，不再占用 worker 或阻塞线程池。
const UNUSABLE_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[cfg(test)]
mod tests {
    use super::UNUSABLE_PASSWORD_HASH;
    use argon2::{
        Argon2,
        password_hash::{PasswordHash, PasswordVerifier},
    };

    /// Issue #342 的回归锁：常量必须是合法 PHC 串。若它无法被 `PasswordHash::new`
    /// 解析，将来任何校验路径都会在解析处提前失败，不变量悄悄变味。
    #[test]
    fn unusable_password_hash_is_a_valid_phc_string() {
        let parsed = PasswordHash::new(UNUSABLE_PASSWORD_HASH)
            .expect("unusable password hash must be parseable");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert!(parsed.salt.is_some(), "hash must carry a salt");
        assert!(parsed.hash.is_some(), "hash must carry a digest");
    }

    /// 常量参数必须与 `Argon2::default()` 一致（argon2id、v=19、m=19456、t=2、p=1）。
    /// 若将来有人真的拿它做口令校验，计算代价必须等于默认参数，不能把
    /// 「校验外部用户口令」意外变成廉价快路径。
    #[test]
    fn unusable_password_hash_matches_default_argon2_cost() {
        let parsed = PasswordHash::new(UNUSABLE_PASSWORD_HASH).expect("valid PHC string");
        let params: std::collections::HashMap<_, _> = parsed
            .params
            .iter()
            .map(|(key, value)| (key.as_str().to_owned(), value.to_string()))
            .collect();
        assert_eq!(params.get("m").map(String::as_str), Some("19456"));
        assert_eq!(params.get("t").map(String::as_str), Some("2"));
        assert_eq!(params.get("p").map(String::as_str), Some("1"));
        assert_eq!(parsed.version, Some(19));
    }

    /// 「不可用」的核心不变量：任何候选口令都校验失败。随机口令在建号时即被
    /// 丢弃，常量哈希的原像不可知，登录路径即使放开也不可能命中。
    #[test]
    fn unusable_password_hash_never_accepts_a_password() {
        let parsed = PasswordHash::new(UNUSABLE_PASSWORD_HASH).expect("valid PHC string");
        for candidate in ["", "password", "oauth_external_user"] {
            assert!(
                Argon2::default()
                    .verify_password(candidate.as_bytes(), &parsed)
                    .is_err(),
                "candidate {candidate:?} must not verify against the unusable hash"
            );
        }
    }
}
