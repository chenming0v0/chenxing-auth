use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use super::credentials::MAX_PASSWORD_LENGTH;

pub const MIN_PASSWORD_LENGTH: usize = 10;
pub const MIN_USERNAME_LENGTH: usize = 3;
pub const MAX_USERNAME_LENGTH: usize = 64;

/// 登录标识符长度上界（字符数，Issue #259）。
///
/// 254 是 RFC 5321 对邮件地址的长度上限，用户名上界（64）被它完全覆盖，
/// 因此一个常量同时约束"邮箱或用户名"两种标识符形态。
///
/// 这个上界必须在标识符进入 SQL 之前生效。`find_credentials_by_identifier` 用
/// `WHERE email = $1 OR username = $1` 查询，绑定参数虽然不存在注入问题，但把
/// 数 MB 的字符串交给 Postgres 逐行比较，等于用一个请求换取一次全表扫描级的
/// 无谓开销。审计侧同理：标识符会被哈希成 `account_ref`，哈希输入越大越亏。
pub const MAX_IDENTIFIER_LENGTH: usize = 254;
pub const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "owner",
    "root",
    "security",
    "service",
    "support",
    "superadmin",
    "superuser",
    "sysadmin",
    "system",
];
pub type UserId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
    Owner,
}

/// 账号状态词表。
///
/// 与 `UserRole` 对齐：业务代码通过这个枚举解析和表示状态，持久化层仍使用
/// 数据库约束要求的文本值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPermission {
    ManageUsers,
    ManageClients,
    ReadAudit,
    ManageSettings,
    ManageIdentityProviders,
    RotateKeys,
    ManageRoles,
}

impl UserRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub const fn allows(self, permission: UserPermission) -> bool {
        match self {
            Self::User => false,
            Self::Admin => matches!(
                permission,
                UserPermission::ManageUsers
                    | UserPermission::ManageClients
                    | UserPermission::ReadAudit
                    | UserPermission::ManageSettings
                    | UserPermission::ManageIdentityProviders
            ),
            Self::Owner => true,
        }
    }

    pub const fn is_at_least(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Owner, _) | (Self::Admin, Self::Admin | Self::User) | (Self::User, Self::User)
        )
    }
}

#[derive(Deserialize)]
pub struct RegistrationInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

impl fmt::Debug for RegistrationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct LoginInput {
    #[serde(alias = "email")]
    pub identifier: String,
    pub password: String,
    pub totp_code: Option<String>,
}

impl fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginInput")
            .field("identifier", &self.identifier)
            .field("password", &"<redacted>")
            .field("totp_code", &self.totp_code.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedLogin {
    pub identifier: String,
    pub password: String,
}

impl fmt::Debug for ValidatedLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedLogin")
            .field("identifier", &self.identifier)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    #[error("username or email is invalid")]
    InvalidIdentifier,
    #[error("password is empty")]
    EmptyPassword,
    /// Issue #259：登录侧的口令长度上界。
    ///
    /// 注册和改密自 Issue #122 起就有上界，登录没有。攻击者不需要账号，
    /// 只要 POST 一个数 MB 的 `password` 就能让服务端对哑哈希跑一次超长
    /// Argon2——"用户不存在"路径的计时填充在这里反而成了放大器，因为它
    /// 保证了无论账号存不存在都必然执行一次哈希。
    ///
    /// 限流按请求计数，拦不住单请求的计算量，所以必须在校验阶段拒绝。
    #[error("password is too long")]
    PasswordTooLong,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedRegistration {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

impl fmt::Debug for ValidatedRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedRegistration")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// 一次用户创建的完整意图。
///
/// 公开注册、管理侧创建和特权用户创建三条路径只在 (role, status) 上有差异，
/// 把它们和已校验的注册信息绑在一起，仓储层就只需要一个插入函数，
/// 调用方也不再在 SQL 里硬编码 `'active'` 或 `UserRole::User`。
/// 明文口令不属于本结构的职责：调用方在哈希前 take 走 `registration.password`。
#[derive(Clone, PartialEq, Eq)]
pub struct UserCreation {
    pub registration: ValidatedRegistration,
    pub role: UserRole,
    pub status: UserStatus,
}

impl fmt::Debug for UserCreation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCreation")
            .field("registration", &self.registration)
            .field("role", &self.role)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("username is invalid")]
    InvalidUsername,
    #[error("email is invalid")]
    InvalidEmail,
    #[error("password must be at least {MIN_PASSWORD_LENGTH} characters")]
    PasswordTooShort,
    /// Issue #122：口令长度上界。
    ///
    /// Argon2 的开销随口令长度增长，无上界时单个请求可以提交数 MB 明文，
    /// 把一次哈希从 50 ms 放大到数秒。限流按请求计数，拦不住单请求的计算量，
    /// 所以必须在校验阶段直接拒绝。
    #[error("password must be at most {MAX_PASSWORD_LENGTH} characters")]
    PasswordTooLong,
    #[error("display name is too long")]
    DisplayNameTooLong,
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub fn validate_registration(
    input: RegistrationInput,
) -> Result<ValidatedRegistration, RegistrationError> {
    let email = normalize_email(&input.email);
    if !is_valid_email(&email) {
        return Err(RegistrationError::InvalidEmail);
    }
    validate_password_length(&input.password)?;

    let display_name = validate_display_name(input.display_name)?;
    let username = validate_username(&input.username).ok_or(RegistrationError::InvalidUsername)?;

    Ok(ValidatedRegistration {
        username,
        email,
        password: input.password,
        display_name,
    })
}

/// 口令长度双向校验（Issue #122）。
///
/// 按字符数而不是字节数计：UTF-8 下一个中文字符占 3 字节，用字节数会让中文口令
/// 的实际长度要求与 ASCII 口令不一致。
///
/// 注册与改密共用这一个入口，两条路径的上下界不允许出现漂移。
pub fn validate_password_length(password: &str) -> Result<(), RegistrationError> {
    let length = password.chars().count();
    if length < MIN_PASSWORD_LENGTH {
        return Err(RegistrationError::PasswordTooShort);
    }
    if length > MAX_PASSWORD_LENGTH {
        return Err(RegistrationError::PasswordTooLong);
    }
    Ok(())
}

pub fn validate_display_name(
    display_name: Option<String>,
) -> Result<Option<String>, RegistrationError> {
    let display_name = display_name.and_then(|name| {
        let name = name.trim().to_owned();
        (!name.is_empty()).then_some(name)
    });
    if display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 128)
    {
        return Err(RegistrationError::DisplayNameTooLong);
    }
    Ok(display_name)
}

/// 登录输入校验（Issue #259 补齐长度上界）。
///
/// 长度上界先于形态判定：长度检查是 O(n) 且不分配，而归一化会为标识符复制一份
/// 新串。超长标识符在这里被挡掉，后面的 `trim().to_ascii_lowercase()` 就不会为
/// 一个数 MB 的输入分配内存，`is_valid_email` 也不会对它做全串扫描。
///
/// 三个上界的作用点各不相同：
/// - 标识符上界挡住进入 SQL 与审计哈希的超长串；
/// - 口令上界挡住进入 Argon2 的超长明文；
/// - 空口令仍然单独判定，错误语义与既有行为一致。
///
/// 判定顺序保持"标识符形态 → 口令"，与补丁前一致：两类错误在服务层都归一为
/// `InvalidLoginInput`，但顺序变化会改变同时违反两项时的错误取值，没有必要动。
///
/// 登录侧只校验上界，不校验 `MIN_PASSWORD_LENGTH`：下界是注册期策略，
/// 在登录期套用会让"下界收紧之前设置的存量短口令"直接无法登录。
pub fn validate_login(input: LoginInput) -> Result<ValidatedLogin, LoginError> {
    if input.identifier.chars().count() > MAX_IDENTIFIER_LENGTH {
        return Err(LoginError::InvalidIdentifier);
    }
    let identifier = input.identifier.trim().to_ascii_lowercase();
    if !is_valid_email(&identifier) && validate_username(&identifier).is_none() {
        return Err(LoginError::InvalidIdentifier);
    }
    if input.password.is_empty() {
        return Err(LoginError::EmptyPassword);
    }
    if input.password.chars().count() > MAX_PASSWORD_LENGTH {
        return Err(LoginError::PasswordTooLong);
    }

    Ok(ValidatedLogin {
        identifier,
        password: input.password,
    })
}

pub fn validate_username(username: &str) -> Option<String> {
    if username.chars().any(char::is_control) {
        return None;
    }
    let username = username.trim().to_ascii_lowercase();
    let length = username.chars().count();
    if !(MIN_USERNAME_LENGTH..=MAX_USERNAME_LENGTH).contains(&length)
        || !username.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        || RESERVED_USERNAMES.contains(&username.as_str())
    {
        return None;
    }
    Some(username)
}

pub fn is_valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !email.chars().any(char::is_whitespace)
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[cfg(test)]
mod public_user_tests {
    use super::{PublicUser, UserRole};

    #[test]
    fn public_user_serializes_creation_time_as_rfc3339() {
        let value = serde_json::to_value(PublicUser {
            id: 1,
            username: "owner".to_owned(),
            email: "owner@example.test".to_owned(),
            display_name: None,
            status: "active".to_owned(),
            role: UserRole::Owner,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("public user serializes");

        assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
    }
}
