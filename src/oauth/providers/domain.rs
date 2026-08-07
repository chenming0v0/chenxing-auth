use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use thiserror::Error;
use url::{Host, Url};

const MAX_NAME_LENGTH: usize = 128;
const MAX_SLUG_LENGTH: usize = 64;
const MAX_CLAIM_PATH_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    #[default]
    Basic,
    RequestBody,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ProviderInput {
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    pub name_claim: Option<String>,
    pub email_verified_claim: Option<String>,
    #[serde(default)]
    pub client_auth_method: ClientAuthMethod,
    /// 是否对该外部 IdP 使用 PKCE（RFC 9700 §2.1.1 要求所有授权码流程都用 PKCE）。
    /// 默认开启；只有确认外部 IdP 不支持 PKCE 时才显式关闭，不做全局禁用。
    #[serde(default = "default_pkce_enabled")]
    pub pkce_enabled: bool,
}

impl fmt::Debug for ProviderInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderInput")
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .field("scopes", &self.scopes)
            .field("subject_claim", &self.subject_claim)
            .field("email_claim", &self.email_claim)
            .field("name_claim", &self.name_claim)
            .field("email_verified_claim", &self.email_verified_claim)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: Option<String>,
    pub email_verified_claim: Option<String>,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
    pub status: String,
    pub client_secret_configured: bool,
}

#[derive(Clone)]
pub struct ValidatedProviderInput {
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: Option<String>,
    pub email_verified_claim: Option<String>,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
}

impl fmt::Debug for ValidatedProviderInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedProviderInput")
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .field("scopes", &self.scopes)
            .field("subject_claim", &self.subject_claim)
            .field("email_claim", &self.email_claim)
            .field("name_claim", &self.name_claim)
            .field("email_verified_claim", &self.email_verified_claim)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .finish()
    }
}

#[derive(Clone)]
pub struct ProviderRecord {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub client_id: String,
    pub client_secret_ciphertext: Vec<u8>,
    pub scopes: Vec<String>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: Option<String>,
    pub email_verified_claim: Option<String>,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
    pub status: String,
}

impl fmt::Debug for ProviderRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret_ciphertext", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("subject_claim", &self.subject_claim)
            .field("email_claim", &self.email_claim)
            .field("name_claim", &self.name_claim)
            .field("email_verified_claim", &self.email_verified_claim)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .field("status", &self.status)
            .finish()
    }
}

impl ProviderInput {
    pub fn validate(self) -> Result<ValidatedProviderInput, ProviderValidationError> {
        let name = self.name.trim().to_owned();
        if name.is_empty() || name.chars().count() > MAX_NAME_LENGTH {
            return Err(ProviderValidationError::InvalidName);
        }
        let slug = self.slug.trim().to_owned();
        if slug.is_empty()
            || slug.chars().count() > MAX_SLUG_LENGTH
            || !slug.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '-'
                    || character == '_'
            })
        {
            return Err(ProviderValidationError::InvalidSlug);
        }
        let authorization_endpoint = validate_endpoint(&self.authorization_endpoint)?;
        let token_endpoint = validate_endpoint(&self.token_endpoint)?;
        let userinfo_endpoint = validate_endpoint(&self.userinfo_endpoint)?;
        let client_id = self.client_id.trim().to_owned();
        if client_id.is_empty() || client_id.chars().count() > 512 {
            return Err(ProviderValidationError::InvalidClientId);
        }
        if self.client_secret.as_ref().is_some_and(String::is_empty) {
            return Err(ProviderValidationError::InvalidClientSecret);
        }
        let scopes = normalize_scopes(self.scopes)?;
        let subject_claim = validate_claim_path(self.subject_claim)?;
        let email_claim = validate_claim_path(self.email_claim)?;
        let name_claim = self.name_claim.map(validate_claim_path).transpose()?;
        let email_verified_claim = self
            .email_verified_claim
            .map(validate_claim_path)
            .transpose()?;

        Ok(ValidatedProviderInput {
            name,
            slug,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            client_id,
            client_secret: self.client_secret,
            scopes,
            subject_claim,
            email_claim,
            name_claim,
            email_verified_claim,
            client_auth_method: self.client_auth_method,
            pkce_enabled: self.pkce_enabled,
        })
    }
}

impl ProviderRecord {
    pub fn summary(&self) -> ProviderSummary {
        ProviderSummary {
            id: self.id,
            name: self.name.clone(),
            slug: self.slug.clone(),
            authorization_endpoint: self.authorization_endpoint.to_string(),
            token_endpoint: self.token_endpoint.to_string(),
            userinfo_endpoint: self.userinfo_endpoint.to_string(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
            subject_claim: self.subject_claim.clone(),
            email_claim: self.email_claim.clone(),
            name_claim: self.name_claim.clone(),
            email_verified_claim: self.email_verified_claim.clone(),
            client_auth_method: self.client_auth_method,
            pkce_enabled: self.pkce_enabled,
            status: self.status.clone(),
            client_secret_configured: !self.client_secret_ciphertext.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalUser {
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
}

impl ExternalUser {
    pub fn from_claims(
        claims: &Value,
        provider: &ValidatedProviderInput,
    ) -> Result<Self, ProviderValidationError> {
        let subject = claim_string(claims, &provider.subject_claim)
            .filter(|value| !value.trim().is_empty())
            .ok_or(ProviderValidationError::MissingSubject)?;
        let email = claim_string(claims, &provider.email_claim)
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| is_valid_email(value))
            .ok_or(ProviderValidationError::InvalidEmail)?;
        let email_verified = provider
            .email_verified_claim
            .as_deref()
            .map(|path| {
                extract_claim(claims, path)
                    .and_then(Value::as_bool)
                    .ok_or(ProviderValidationError::EmailNotVerified)
            })
            .transpose()?
            .unwrap_or(false);
        if provider.email_verified_claim.is_some() && !email_verified {
            return Err(ProviderValidationError::EmailNotVerified);
        }
        let name = provider
            .name_claim
            .as_deref()
            .and_then(|path| claim_string(claims, path))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());

        Ok(Self {
            subject,
            email,
            name,
            email_verified,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderValidationError {
    #[error("provider name is invalid")]
    InvalidName,
    #[error("provider slug is invalid")]
    InvalidSlug,
    #[error("provider endpoint is invalid")]
    InvalidEndpoint,
    #[error("provider client id is invalid")]
    InvalidClientId,
    #[error("provider client secret is invalid")]
    InvalidClientSecret,
    #[error("provider scope is invalid")]
    InvalidScope,
    #[error("provider claim path is invalid")]
    InvalidClaimPath,
    #[error("external subject is missing")]
    MissingSubject,
    #[error("external email is invalid")]
    InvalidEmail,
    #[error("external email is not verified")]
    EmailNotVerified,
}

pub fn extract_claim<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(claims, |value, part| value.get(part))
}

fn claim_string(claims: &Value, path: &str) -> Option<String> {
    extract_claim(claims, path).and_then(|value| value.as_str().map(str::to_owned))
}

fn validate_endpoint(value: &str) -> Result<Url, ProviderValidationError> {
    let url = Url::parse(value.trim()).map_err(|_| ProviderValidationError::InvalidEndpoint)?;
    validate_endpoint_url(&url)?;
    Ok(url)
}

pub fn validate_endpoint_url(url: &Url) -> Result<(), ProviderValidationError> {
    let host = url.host_str();
    let allowed_scheme = match url.scheme() {
        "https" => true,
        "http" => is_loopback_host(url),
        _ => false,
    };
    if !matches!(url.scheme(), "http" | "https")
        || host.is_none()
        || !allowed_scheme
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderValidationError::InvalidEndpoint);
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn normalize_scopes(scopes: Vec<String>) -> Result<Vec<String>, ProviderValidationError> {
    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.trim().to_owned();
        if scope.is_empty()
            || scope.chars().count() > 128
            || scope.chars().any(char::is_whitespace)
            || normalized.contains(&scope)
        {
            return Err(ProviderValidationError::InvalidScope);
        }
        normalized.push(scope);
    }
    if normalized.is_empty() {
        return Err(ProviderValidationError::InvalidScope);
    }
    Ok(normalized)
}

fn validate_claim_path(value: String) -> Result<String, ProviderValidationError> {
    let path = value.trim().to_owned();
    if path.is_empty()
        || path.chars().count() > MAX_CLAIM_PATH_LENGTH
        || !path.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
    {
        return Err(ProviderValidationError::InvalidClaimPath);
    }
    Ok(path)
}

fn is_valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !local.is_empty()
        && domain.contains('.')
        && !email.chars().any(char::is_whitespace)
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}
fn default_email_claim() -> String {
    "email".to_owned()
}

/// PKCE 默认开启：RFC 9700 §2.1.1 要求所有授权码流程都使用 PKCE。
/// 未显式提供该字段的旧请求体自动获得安全默认值。
fn default_pkce_enabled() -> bool {
    true
}
