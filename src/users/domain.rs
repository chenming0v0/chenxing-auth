use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use super::credentials::MAX_PASSWORD_LENGTH;
use super::email::{EmailAddress, MAX_EMAIL_LENGTH};

pub const MIN_PASSWORD_LENGTH: usize = 10;
pub const MIN_USERNAME_LENGTH: usize = 3;
pub const MAX_USERNAME_LENGTH: usize = 64;

/// 登录标识符长度上界（字符数，Issue #259）。
///
/// 取值与 [`MAX_EMAIL_LENGTH`] 相同（RFC 5321 的 254），用户名上界（64）被它
/// 完全覆盖，因此一个常量同时约束"邮箱或用户名"两种标识符形态。别名到邮箱侧的
/// 常量而不是再写一个字面量：两个上界必须同步，写两遍就会漂移。
///
/// 这个上界必须在标识符进入 SQL 之前生效。凭据查询会把标识符绑进 SQL，绑定参数
/// 虽然不存在注入问题，但把数 MB 的字符串交给 Postgres 逐行比较，等于用一个请求
/// 换取一次全表扫描级的无谓开销。审计侧同理：标识符会被哈希成 `account_ref`，
/// 哈希输入越大越亏。
pub const MAX_IDENTIFIER_LENGTH: usize = MAX_EMAIL_LENGTH;
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
/// The first-owner bootstrap transaction resets the users sequence so this identity is stable.
pub const INITIAL_OWNER_ID: UserId = 1;

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

    /// 守卫口径下的「活跃」判定：只要状态不是明确的 `disabled` 就算活跃。
    ///
    /// 未知状态串（手工改库、未来新增状态值、大小写漂移）按 fail-closed 处理：
    /// 宁可拒绝降级/禁用，也不允许静默移除最后一个可用 Owner。
    /// 该谓词必须与 `role_guard::lock_active_owner_scope` 的 SQL 谓词
    /// `status <> 'disabled'` 保持一致（Issue #358）。
    pub fn is_active(value: &str) -> bool {
        Self::parse(value) != Some(Self::Disabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPermission {
    ManageUsers,
    ManageClients,
    ReadAudit,
    ManageSettings,
    ManageIdentityProviders,
    /// 修改 OIDC 发行者信任锚，只授予 Owner。
    ManageIssuer,
    RotateKeys,
    ManageRoles,
    /// 重置他人的认证因子。独立于 `ManageUsers`：删除一个账号的 TOTP 或 Passkey
    /// 会把它降级到「只有密码」（或只剩另一个因子），是账号接管链条上的一环，
    /// 因此按最小权限只授予 Owner。末位 Owner 丢失全部 Passkey 时不能走 Session
    /// 通道，必须用系统 `ADMIN_TOKEN`（#460）。
    ManageAuthFactors,
}

/// 以用户为目标的管理写操作所持有的授权档位。
///
/// 目标是否为 Owner 必须在写事务持有目标行锁后判定（Issue #323）。把档位作为
/// 显式值传入仓储层，而不是传一个容易写反的布尔值：`ManageUsers` 可以改普通用户，
/// 只有 `ManageRoles` 可以改事务中实际读到的 Owner。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerTargetAccess {
    ManageUsers,
    ManageRoles,
}

impl OwnerTargetAccess {
    pub const fn permits_owner(self) -> bool {
        matches!(self, Self::ManageRoles)
    }
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

    pub const fn is_privileged(self) -> bool {
        matches!(self, Self::Admin | Self::Owner)
    }

    pub const fn allows(self, permission: UserPermission) -> bool {
        match self {
            Self::User => false,
            // Admin 故意不含 ManageAuthFactors 与 RotateKeys：两者都能把账号或
            // 密钥状态改到「更容易被接管」的方向，属于 Owner 保留权限。
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

/// 一次已完成的第一因子认证结果。
///
/// 只带 `UserId` 是不够的（Issue #274）。口令校验读取的是某一时刻的
/// `password_hash`，而 `session_epoch` 与该哈希在同一行、同一次读取里取出，
/// 因此它就是"这次认证所依据的凭据版本"。后续签发凭据（login ticket、Session）
/// 必须原子地确认这个版本没有前进：并发改密会在同一事务里改哈希并把
/// `session_epoch + 1`，旧口令的认证结果一旦被套用到新 epoch 上，改密的撤销
/// 语义就被绕过了——旧口令刚被作废，却仍然换出了一张按新 epoch 计算的有效凭据。
///
/// 不新增列：`session_epoch` 已经是会话撤销水位，复用它即可，不需要"认证版本号"
/// 这种第二套并行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub id: UserId,
    /// 读取 `password_hash` 时同一行上的 `session_epoch`。
    pub session_epoch: i64,
}

impl AuthenticatedUser {
    pub const fn new(id: UserId, session_epoch: i64) -> Self {
        Self { id, session_epoch }
    }
}

/// 登录标识符的两种形态。
///
/// 补丁前是一个 `String`，仓储层用 `WHERE email = $1 OR username = $1` 同时试两列。
/// 现在邮箱的匹配列是 `canonical_email` 而用户名仍是 `username`，两列的规范化
/// 规则完全不同（一个走 IDNA，一个走 ASCII 小写 + 字符白名单），一个字符串再也
/// 无法同时代表两者。
///
/// 用枚举而不是"两个 Option"：标识符含 `@` 就必须是邮箱，不含就必须是用户名，
/// 二者互斥。枚举让这个互斥性由类型保证，仓储层因此不需要判断"该查哪一列"。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LoginIdentifier {
    /// 已规范化的邮箱；匹配用 [`EmailAddress::canonical`]。
    Email(EmailAddress),
    /// 已规范化的用户名（ASCII 小写）。
    Username(String),
}

impl LoginIdentifier {
    /// 限流与审计使用的账号维度键。
    ///
    /// 用匹配值而不是原始输入：`USER@ÉXAMPLE.COM` 与 `user@xn--xample-9ua.com`
    /// 指向同一个账号，若按原始输入分桶，攻击者只要变换书写就能重置失败计数。
    pub fn limiter_key(&self) -> &str {
        match self {
            Self::Email(email) => email.canonical(),
            Self::Username(username) => username,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedLogin {
    pub identifier: LoginIdentifier,
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
    /// 已规范化的邮箱。持有 [`EmailAddress`] 而不是 `String`，是为了让"展示值与
    /// 匹配值必须成对写库"这件事由类型保证：仓储层拿不到只有一个值的注册意图。
    pub email: EmailAddress,
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

pub fn validate_registration(
    input: RegistrationInput,
) -> Result<ValidatedRegistration, RegistrationError> {
    // 规范化与校验是同一步：`EmailAddress::parse` 成功即两个值都已算出，
    // 不存在"校验通过但忘了规范化"的中间状态（Issue #302）。
    let email = EmailAddress::parse(&input.email).map_err(|_| RegistrationError::InvalidEmail)?;
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

/// 认证用口令边界：登录 `password` 与改密 `current_password` 共用（Issue #462）。
///
/// 只拦空口令和超过 [`MAX_PASSWORD_LENGTH`] 的明文。不套用
/// [`MIN_PASSWORD_LENGTH`]：下界是注册期策略，认证期套用会锁死存量短口令。
pub fn validate_authentication_password(password: &str) -> Result<(), LoginError> {
    if password.is_empty() {
        return Err(LoginError::EmptyPassword);
    }
    if password.chars().count() > MAX_PASSWORD_LENGTH {
        return Err(LoginError::PasswordTooLong);
    }
    Ok(())
}

/// 登录输入校验（Issue #259 补齐长度上界）。
///
/// 长度上界先于形态判定：长度检查是 O(n) 且不分配，而规范化会为标识符复制一份
/// 新串。超长标识符在这里被挡掉，`EmailAddress::parse` 的 UTS-46 处理就不会为
/// 一个数 MB 的输入分配 Unicode 映射缓冲区。
///
/// 三个上界的作用点各不相同：
/// - 标识符上界挡住进入 SQL 与审计哈希的超长串；
/// - 口令上界挡住进入 Argon2 的超长明文；
/// - 空口令仍然单独判定，错误语义与既有行为一致。
///
/// 判定顺序保持"标识符形态 → 口令"，与补丁前一致：两类错误在服务层都归一为
/// `InvalidLoginInput`，但顺序变化会改变同时违反两项时的错误取值，没有必要动。
///
/// 口令边界走 [`validate_authentication_password`]，与改密当前口令同一套规则。
pub fn validate_login(input: LoginInput) -> Result<ValidatedLogin, LoginError> {
    if input.identifier.chars().count() > MAX_IDENTIFIER_LENGTH {
        return Err(LoginError::InvalidIdentifier);
    }
    let identifier = parse_login_identifier(input.identifier.trim())?;
    validate_authentication_password(&input.password)?;

    Ok(ValidatedLogin {
        identifier,
        password: input.password,
    })
}

/// 判定标识符形态并按对应规则规范化。
///
/// `@` 是判据：用户名字符白名单（`[a-z0-9._-]`）不含 `@`，所以含 `@` 的输入不可能
/// 是合法用户名。先分流再规范化，而不是"两种规则都试一遍取先成功的"——后者会让
/// 一个输入在两条规范化路径上产生两个不同的键，取哪个取决于判定顺序。
pub fn parse_login_identifier(identifier: &str) -> Result<LoginIdentifier, LoginError> {
    if identifier.contains('@') {
        return EmailAddress::parse(identifier)
            .map(LoginIdentifier::Email)
            .map_err(|_| LoginError::InvalidIdentifier);
    }
    validate_username(identifier)
        .map(LoginIdentifier::Username)
        .ok_or(LoginError::InvalidIdentifier)
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

#[cfg(test)]
#[path = "domain_email_tests.rs"]
mod email_tests;

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
#[path = "domain_public_user_tests.rs"]
mod public_user_tests;
