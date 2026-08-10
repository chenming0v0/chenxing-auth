use std::{sync::Arc, time::Duration};

use super::{
    claims::ExternalUser,
    client_pkce::s256_code_challenge,
    domain::{
        ClientAuthMethod, ProviderInput, ProviderRecord, ProviderSummary, ProviderValidationError,
    },
    endpoint_policy::{PublicEndpointResolver, validate_endpoint_url},
    repository::{self, CreateIdentityError},
    secrets::{SecretError, SecretManager},
};
use crate::users::domain::{UserId, UserStatus};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::fmt;
use thiserror::Error;

const EXTERNAL_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ExternalOAuthService {
    pool: crate::sqlx::PgPool,
    secrets: SecretManager,
    http: Client,
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
    ) -> Result<Self, ExternalOAuthError> {
        let http = Client::builder()
            .timeout(EXTERNAL_HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            // Issue #291：域名端点的实际指向只有解析后才知道。把筛查放进解析器，
            // 交出的地址就是随后建连使用的地址，不留 DNS rebinding 时间窗。
            .dns_resolver(Arc::new(PublicEndpointResolver))
            .build()
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        Ok(Self {
            pool,
            secrets,
            http,
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
        let validated = input.validate()?;
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
        let validated = input.validate()?;
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
            validate_endpoint_url(&provider.authorization_endpoint)?;
            validate_endpoint_url(&provider.token_endpoint)?;
            validate_endpoint_url(&provider.userinfo_endpoint)?;
        }
        Ok(repository::set_status(&self.pool, slug, status).await?)
    }

    /// 构造发往外部 IdP 的授权请求 URL。
    ///
    /// `code_verifier` 为空串时不追加 PKCE 参数，覆盖两种情况：
    /// 1. provider 显式关闭了 PKCE（`pkce_enabled = false`，外部 IdP 不支持）。
    /// 2. 滚动升级期间从 Redis 取出的旧 state 没有 verifier。
    ///
    /// 其余情况按 RFC 9700 §2.1.1 一律附带 S256 challenge。
    pub fn authorization_url(
        &self,
        provider: &ProviderRecord,
        callback_uri: &str,
        state: &str,
        code_verifier: &str,
    ) -> Result<String, ExternalOAuthError> {
        validate_endpoint_url(&provider.authorization_endpoint)?;
        let mut url = provider.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &provider.client_id);
            query.append_pair("redirect_uri", callback_uri);
            query.append_pair("scope", &provider.scopes.join(" "));
            query.append_pair("state", state);
            if !code_verifier.is_empty() {
                // RFC 7636 §4.3：challenge 随授权请求发送，verifier 留在本地。
                query.append_pair("code_challenge", &s256_code_challenge(code_verifier));
                query.append_pair("code_challenge_method", "S256");
            }
        }
        Ok(url.to_string())
    }

    /// 用授权码向外部 IdP 换取 access token。
    ///
    /// `code_verifier` 非空时按 RFC 7636 §4.5 附带 `code_verifier`，把授权码绑定到
    /// 发起授权请求的这一次会话；泄露的 `code` 在没有 verifier 的情况下无法被重放。
    pub async fn exchange_code(
        &self,
        provider: &ProviderRecord,
        callback_uri: &str,
        code: &str,
        code_verifier: &str,
    ) -> Result<ExternalToken, ExternalOAuthError> {
        validate_endpoint_url(&provider.token_endpoint)?;
        let secret = self.decrypt_secret(provider)?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", callback_uri),
        ];
        if !code_verifier.is_empty() {
            form.push(("code_verifier", code_verifier));
        }
        let request = match provider.client_auth_method {
            ClientAuthMethod::Basic => self
                .http
                .post(provider.token_endpoint.clone())
                .basic_auth(&provider.client_id, Some(secret))
                .form(&form),
            ClientAuthMethod::RequestBody => {
                form.push(("client_id", provider.client_id.as_str()));
                form.push(("client_secret", secret.as_str()));
                self.http.post(provider.token_endpoint.clone()).form(&form)
            }
        };
        let response = request
            .send()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        if response.status() != StatusCode::OK {
            return Err(ExternalOAuthError::RemoteRequest);
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        let access_token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ExternalOAuthError::RemoteRequest)?;
        Ok(ExternalToken {
            access_token: access_token.to_owned(),
            token_type: payload
                .get("token_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    pub async fn userinfo(
        &self,
        provider: &ProviderRecord,
        token: &ExternalToken,
    ) -> Result<ExternalUser, ExternalOAuthError> {
        validate_endpoint_url(&provider.userinfo_endpoint)?;
        let response = self
            .http
            .get(provider.userinfo_endpoint.clone())
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        if response.status() != StatusCode::OK {
            return Err(ExternalOAuthError::RemoteRequest);
        }
        let claims: Value = response
            .json()
            .await
            .map_err(|_| ExternalOAuthError::RemoteRequest)?;
        // 映射构造失败说明存储行本身不可用（缺 email_verified_claim 的存量行），
        // 这是配置错误而不是外部响应错误，用 Validation 区分开来。
        let mapping = provider.claim_mapping()?;
        ExternalUser::from_claims(&claims, &mapping).map_err(|error| match error {
            ProviderValidationError::EmailNotVerified => ExternalOAuthError::EmailNotVerified,
            _ => ExternalOAuthError::InvalidUserInfo,
        })
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

    fn decrypt_secret(&self, provider: &ProviderRecord) -> Result<String, ExternalOAuthError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::client_pkce::generate_code_verifier;
    use url::Url;

    /// 构造仅用于 URL 拼装测试的 service：`connect_lazy` 不会真正连接数据库，
    /// 而 `authorization_url` 是纯函数，不触碰连接池。
    fn service() -> ExternalOAuthService {
        let pool = crate::sqlx::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        ExternalOAuthService::new(pool, SecretManager::from_key([7_u8; 32])).expect("service")
    }

    fn provider(pkce_enabled: bool) -> ProviderRecord {
        ProviderRecord {
            id: 1,
            name: "Mock".to_owned(),
            slug: "mock".to_owned(),
            authorization_endpoint: Url::parse("https://idp.example.com/authorize")
                .expect("authorize URL"),
            token_endpoint: Url::parse("https://idp.example.com/token").expect("token URL"),
            userinfo_endpoint: Url::parse("https://idp.example.com/userinfo")
                .expect("userinfo URL"),
            client_id: "mock-client".to_owned(),
            client_secret_ciphertext: vec![1, 2, 3],
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            subject_claim: "sub".to_owned(),
            email_claim: "email".to_owned(),
            name_claim: None,
            email_verified_claim: Some("email_verified".to_owned()),
            client_auth_method: ClientAuthMethod::Basic,
            pkce_enabled,
            status: "active".to_owned(),
        }
    }

    fn query_value(url: &str, key: &str) -> Option<String> {
        Url::parse(url)
            .expect("authorization URL")
            .query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    }

    /// RFC 9700 §2.1.1 / RFC 7636 §4.3：授权请求必须带 S256 challenge。
    #[tokio::test]
    async fn authorization_url_appends_s256_challenge() {
        let verifier = generate_code_verifier();
        let url = service()
            .authorization_url(
                &provider(true),
                "https://auth.example.com/auth/external/mock/callback",
                "state-value",
                &verifier,
            )
            .expect("authorization URL");
        assert_eq!(
            query_value(&url, "code_challenge_method").as_deref(),
            Some("S256")
        );
        assert_eq!(
            query_value(&url, "code_challenge"),
            Some(s256_code_challenge(&verifier)),
            "challenge 必须是 BASE64URL(SHA256(verifier))"
        );
        // state 是独立的 CSRF 机制，不受 PKCE 影响。
        assert_eq!(query_value(&url, "state").as_deref(), Some("state-value"));
        assert_eq!(query_value(&url, "response_type").as_deref(), Some("code"));
        assert!(
            !url.contains(verifier.as_str()),
            "verifier 绝不能出现在授权 URL 中"
        );
    }

    /// RFC 7636 附录 B 的官方测试向量，端到端校验 URL 中的 challenge 取值。
    #[tokio::test]
    async fn authorization_url_uses_rfc_7636_appendix_b_vector() {
        let url = service()
            .authorization_url(
                &provider(true),
                "https://auth.example.com/auth/external/mock/callback",
                "state-value",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            )
            .expect("authorization URL");
        assert_eq!(
            query_value(&url, "code_challenge").as_deref(),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        );
    }

    /// provider 关闭 PKCE 时（外部 IdP 不支持 RFC 7636），不得附加 PKCE 参数。
    /// 空 verifier 同样覆盖升级期间取出的旧 state。
    #[tokio::test]
    async fn authorization_url_omits_pkce_when_verifier_is_empty() {
        let url = service()
            .authorization_url(
                &provider(false),
                "https://auth.example.com/auth/external/mock/callback",
                "state-value",
                "",
            )
            .expect("authorization URL");
        assert_eq!(query_value(&url, "code_challenge"), None);
        assert_eq!(query_value(&url, "code_challenge_method"), None);
        assert_eq!(query_value(&url, "state").as_deref(), Some("state-value"));
    }
}
