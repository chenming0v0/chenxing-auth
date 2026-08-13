//! 外部 IdP 的 claim 路径映射与身份解析。
//!
//! 这里的核心不是解析代码，而是 `ClaimMapping` 这个数据结构：它把「provider 是否
//! 配置了 `email_verified` claim」这个特殊情况在构造期就消灭掉。构造成功的映射
//! 一定带着一个合法的 `email_verified` 路径，所以下游解析路径上不存在
//! `Option<String>` 分支，也就不存在「没配置就当作通过」的漏放行（Issue #261）。

use serde_json::Value;

use super::domain::ProviderValidationError;
use crate::users::email::EmailAddress;

const MAX_CLAIM_PATH_LENGTH: usize = 128;

/// 一个 provider 的 claim 路径集合，构造即校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMapping {
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    /// 指向布尔型邮箱验证状态的 claim 路径。没有它就没有 provider，
    /// 因此该字段不是 `Option`。
    pub email_verified: String,
}

impl ClaimMapping {
    /// `email_verified` 缺失或为空白时返回 [`ProviderValidationError::MissingEmailVerifiedClaim`]。
    ///
    /// 空白等同缺失：管理端表单和旧脚本都可能提交 `""`，把它当成「已配置」会
    /// 直接退化成 Issue #261 的漏放行。
    pub fn new(
        subject: String,
        email: String,
        name: Option<String>,
        email_verified: Option<String>,
    ) -> Result<Self, ProviderValidationError> {
        let email_verified = email_verified
            .map(|path| path.trim().to_owned())
            .filter(|path| !path.is_empty())
            .ok_or(ProviderValidationError::MissingEmailVerifiedClaim)?;
        Ok(Self {
            subject: validate_claim_path(subject)?,
            email: validate_claim_path(email)?,
            name: name.map(validate_claim_path).transpose()?,
            email_verified: validate_claim_path(email_verified)?,
        })
    }
}

/// 从外部 IdP userinfo 响应中解析出的用户身份。
///
/// 只能通过 [`ExternalUser::from_claims`] 构造，因此 `email_verified` 恒为 `true`；
/// 服务层仍然会再校验一次，作为纵深防御。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalUser {
    pub subject: String,
    /// 已规范化的邮箱（Issue #302）。外部 IdP 返回的书写形态不可控——同一个
    /// 邮箱可能这次返回 `User@Example.com`、下次返回 `user@example.com`。持有
    /// [`EmailAddress`] 让建号路径与本地注册共用同一个匹配值，因此 IdP 的书写
    /// 变化不会绕过"邮箱已注册"判定去建第二个账号。
    pub email: EmailAddress,
    pub name: Option<String>,
    pub email_verified: bool,
}

impl ExternalUser {
    pub fn from_claims(
        claims: &Value,
        mapping: &ClaimMapping,
    ) -> Result<Self, ProviderValidationError> {
        let subject = claim_string(claims, &mapping.subject)
            .filter(|value| !value.trim().is_empty())
            .ok_or(ProviderValidationError::MissingSubject)?;
        let email = claim_string(claims, &mapping.email)
            .and_then(|value| EmailAddress::parse(&value).ok())
            .ok_or(ProviderValidationError::InvalidEmail)?;
        // Fail-closed：claim 缺失、类型不是 bool、或值为 false，一律拒绝。
        // 未验证的邮箱能建号意味着任何人都能用别人的邮箱在本平台开户。
        let email_verified = extract_claim(claims, &mapping.email_verified)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !email_verified {
            return Err(ProviderValidationError::EmailNotVerified);
        }
        let name = mapping
            .name
            .as_deref()
            .and_then(|path| claim_string(claims, path))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());

        Ok(Self {
            subject,
            email,
            name,
            email_verified: true,
        })
    }
}

pub fn extract_claim<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(claims, |value, part| value.get(part))
}

fn claim_string(claims: &Value, path: &str) -> Option<String> {
    extract_claim(claims, path).and_then(|value| value.as_str().map(str::to_owned))
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
