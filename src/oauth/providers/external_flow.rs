//! 与外部 IdP 的协议交互：授权 URL 拼装、授权码兑换、UserInfo 取回。
//!
//! 与 [`super::service`] 的分界是「谁在说话」：那边是本服务对自己数据库里 provider
//! 配置的增删改查，这边是本服务作为客户端对外部 IdP 发起的请求。信任边界全在这一侧，
//! 因此协议约束和信任模型的说明也集中在这里。
//!
//! **信任模型（Issue #296）**：自定义 provider 是 **OAuth 2.0 授权码流程 + UserInfo**，
//! 本服务在这一侧不是 OIDC 依赖方。身份事实只来自用 access token 经 TLS 取回的
//! UserInfo 响应；令牌响应里的 `id_token` 不被解析、不被保存、不参与身份判定。
//!
//! 这不是「OIDC 没做完」，而是一条被明确划定的边界：验证 ID Token 需要 provider 侧的
//! issuer、JWKS、允许算法和 nonce 策略，当前 provider 模型不保存这些，也就不具备执行
//! `iss`/`aud`/`exp`/`iat`/`nonce`/`kid` 与算法白名单校验的条件。在这些配置和验证实现
//! 落地之前，产品、API、UI 和文档一律只声明 OAuth 2.0，不宣称 OIDC。

use reqwest::StatusCode;
use serde_json::Value;

use super::{
    claims::ExternalUser,
    client_pkce::s256_code_challenge,
    domain::{ClientAuthMethod, ProviderRecord, ProviderValidationError},
    endpoint_policy::validate_endpoint_url,
    service::{ExternalOAuthError, ExternalOAuthService, ExternalToken},
};

impl ExternalOAuthService {
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
        validate_endpoint_url(&provider.authorization_endpoint, self.endpoint_policy())?;
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
        validate_endpoint_url(&provider.token_endpoint, self.endpoint_policy())?;
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
                .http()
                .post(provider.token_endpoint.clone())
                .basic_auth(&provider.client_id, Some(secret))
                .form(&form),
            ClientAuthMethod::RequestBody => {
                form.push(("client_id", provider.client_id.as_str()));
                form.push(("client_secret", secret.as_str()));
                self.http()
                    .post(provider.token_endpoint.clone())
                    .form(&form)
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
        parse_token_response(&payload)
    }

    /// 取回外部身份。这是本服务建立外部身份的**唯一**事实来源。
    pub async fn userinfo(
        &self,
        provider: &ProviderRecord,
        token: &ExternalToken,
    ) -> Result<ExternalUser, ExternalOAuthError> {
        validate_endpoint_url(&provider.userinfo_endpoint, self.endpoint_policy())?;
        let response = self
            .http()
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
}

/// 从令牌响应中取出本服务会使用的部分（RFC 6749 §5.1）。
///
/// OAuth-only 契约（Issue #296）在这里是硬约束，而不是注释里的约定：
///
/// - `access_token` 是唯一的成功条件。只返回 `id_token` 的响应一律失败，因此
///   「外部 IdP 给了 ID Token 就算登录成功」这条路径在类型层面不存在。
/// - 响应里的 `id_token` 不被解析、不被保存、不参与身份判定。本服务不是 OIDC
///   依赖方，没有 issuer/JWKS/算法策略，也就不具备验证它的条件；把一个未验证的
///   JWT 传下去比丢掉它危险得多。
pub fn parse_token_response(payload: &Value) -> Result<ExternalToken, ExternalOAuthError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::{
        client_pkce::generate_code_verifier, endpoint_policy::EndpointPolicy,
        secrets::SecretManager,
    };
    use url::Url;

    /// 构造仅用于 URL 拼装测试的 service：`connect_lazy` 不会真正连接数据库，
    /// 而 `authorization_url` 是纯函数，不触碰连接池。生产策略下回环端点被拒，
    /// 与本模块用例（全部使用公网 https 端点）一致。
    fn service() -> ExternalOAuthService {
        let pool = crate::sqlx::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        ExternalOAuthService::new(
            pool,
            SecretManager::from_key([7_u8; 32]),
            EndpointPolicy::PRODUCTION,
        )
        .expect("service")
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

    /// Issue #296：OAuth-only 契约的核心——身份只由 access token + UserInfo 建立。
    ///
    /// 外部 IdP 返回 `id_token` 时必须被丢弃：本服务没有 issuer/JWKS/算法策略，
    /// 无法验证它。保留一个未验证的 JWT 只会诱使后续代码把它当身份断言用。
    #[test]
    fn token_response_discards_id_token_and_keeps_access_token() {
        let token = parse_token_response(&serde_json::json!({
            "access_token": "at-value",
            "token_type": "Bearer",
            "id_token": "eyJhbGciOiJub25lIn0.e30.",
            "expires_in": 3600
        }))
        .expect("access token response");
        assert_eq!(token.access_token, "at-value");
        assert_eq!(token.token_type.as_deref(), Some("Bearer"));
        // 结构里没有 id_token 字段，Debug 输出也不得泄露任何令牌材料。
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("id_token"), "{rendered}");
        assert!(!rendered.contains("at-value"), "{rendered}");
        assert!(!rendered.contains("eyJhbGciOiJub25lIn0"), "{rendered}");
    }

    /// fail-closed：只有 `id_token` 没有 `access_token` 的响应不能算登录成功。
    /// 这类响应来自把 provider 当 OIDC 用的配置，本服务无法验证 ID Token，
    /// 也拿不到 UserInfo，必须直接失败而不是退化成信任 JWT。
    #[test]
    fn token_response_rejects_id_token_only_and_empty_access_token() {
        for payload in [
            serde_json::json!({"id_token": "eyJhbGciOiJub25lIn0.e30.", "token_type": "Bearer"}),
            serde_json::json!({"access_token": "", "id_token": "eyJhbGciOiJub25lIn0.e30."}),
            serde_json::json!({"access_token": 42}),
            serde_json::json!({}),
        ] {
            assert!(
                matches!(
                    parse_token_response(&payload),
                    Err(ExternalOAuthError::RemoteRequest)
                ),
                "{payload} 必须按远端响应无效拒绝"
            );
        }
    }
}
