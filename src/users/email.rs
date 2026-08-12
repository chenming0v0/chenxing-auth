//! 邮箱规范化的唯一入口（Issue #302）。
//!
//! ## 为什么需要一个类型而不是一个函数
//!
//! 补丁前的规范化是 `email.trim().to_ascii_lowercase()`，散落在注册、登录和外部
//! Provider 建号三处。`to_ascii_lowercase` 只动 ASCII 字节，于是
//! `USER@ÉXAMPLE.COM` 落库成 `user@Éxample.com`，而用户下次按常见小写形式输入
//! `user@éxample.com` 时匹配不上——同一个邮箱有了两种"规范"形态，
//! 数据库那条 `UNIQUE (email)` 也就拦不住重复注册。
//!
//! 修复办法不是再加一层字符串替换，而是把"展示值"和"匹配值"分成两个字段并用
//! 一个类型同时产出它们。[`EmailAddress`] 构造即规范化：拿到它就意味着两个值
//! 已经由同一份规则算出，调用方无法只算一个、也无法各自发明规则。
//!
//! ## 规范化策略
//!
//! ### 域名：UTS-46 IDNA 转 ASCII
//!
//! 域名在 DNS 语义上大小写无关，且 Unicode 域名存在多种等价书写（大小写、
//! NFC/NFD、兼容字符、已编码的 Punycode）。UTS-46 是把这些等价形态收敛成
//! 单一 ASCII 表示的标准算法，`idna` crate 是 Rust 生态的标准实现，而且它已经
//! 因为 `url` 被编译进本项目——复用它不新增依赖树，只是把传递依赖显式化。
//!
//! 参数选择：
//!
//! - [`AsciiDenyList::URL`]：拒绝控制字符、空格和 WHATWG 的 forbidden domain
//!   code point。刻意不用 `STD3`，因为 `STD3` 连下划线一起拒绝，而补丁前的
//!   校验是放行的；用 `STD3` 会把存量的 `foo@a_b.example` 账号直接锁死。
//! - [`Hyphens::Allow`]：与 WHATWG URL 一致。`Check` 会拒绝真实存在的域名
//!   （例如第三、四位带连字符的 CDN 主机名）。
//! - [`DnsLength::Verify`]：域名整体 ≤ 253、每个标签 1..=63，且不接受根点。
//!   拒绝根点是必要的：`example.com` 与 `example.com.` 在 DNS 上等价，
//!   允许后者就等于允许同一域名有两种规范形态。
//!
//! 域名同时要求至少一个点。这一条来自补丁前的 `is_valid_email`，保留它是为了
//! 不放宽既有边界（`user@localhost` 仍然被拒）。
//!
//! ### 本地部分：只做 ASCII 大小写折叠
//!
//! RFC 5321 把本地部分的解释权交给收件方 MTA，理论上 `A@x` 与 `a@x` 可以是两个
//! 不同的邮箱。但本项目补丁前已经把整封地址 ASCII 小写后作为唯一键，改成
//! 大小写敏感会让存量的 `Owner@example.com` 账号无法再用同一串登录——
//! 这是 Never break userspace 不允许的。因此匹配值继续对本地部分做
//! **ASCII 小写**，并且只做这一件事：
//!
//! - 不剥离 `+tag` 别名。加号别名是 provider 特定行为（Gmail 有，很多企业邮箱
//!   没有），在认证中枢里统一剥离等于替 provider 猜语义，会把两个真实存在的
//!   独立邮箱合并成一个账号。需要限制别名注册的场景由
//!   `EmailPolicySetting::alias_restriction_enabled` 单独表达，那是准入策略，
//!   不是身份等价规则。
//! - 不剥离点号。同理，`a.b@` 与 `ab@` 只在部分 provider 上等价。但 RFC 5321
//!   的 Dot-string 语法（`Atom *("." Atom)`，Atom 至少一个字符）要求本地部分
//!   不得以点号开头或结尾、也不得含连续点号：这类畸形书写既不是合法地址，又会
//!   在折叠点号的 provider 上与受害者地址语义等价（Issue #347），因此一律拒绝。
//!   拒绝不是归一化——合法的单点号形态（`u.ser@`）继续原样通过。
//! - 不对非 ASCII 做大小写折叠或 NFC 归一。SMTPUTF8 的本地部分是字节敏感的，
//!   替它归一同样是猜语义。非 ASCII 本地部分因此原样进入匹配值：两种书写形态
//!   会被视为两个不同邮箱，这是保守方向的错误（拒绝合并），不是放行方向的。
//!
//! ### 展示值
//!
//! 展示值 = 去空白的原始本地部分（保留大小写）+ IDNA ASCII 域名。
//!
//! 保留本地部分大小写是有意的：补丁前会把 `John.Doe@Example.com` 改写成
//! `john.doe@example.com` 再展示给用户，那是在没有必要的地方篡改用户输入。
//! 域名则统一用 ASCII 形态而不是回显 Unicode：展示值会进入邮件头、TOTP 标签和
//! 管理台列表，Punycode 在这些场景里可传输、可比较，而 Unicode 域名在管理台里
//! 还会带来同形字（homograph）误判风险。
//!
//! 对外 API 的 `email` 字段继续返回展示值，因此契约形状不变。

use std::fmt;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

/// 邮箱地址的字符数上界。
///
/// 254 是 RFC 5321 对 `Path` 的长度上限（含尖括号时 256）。上界在 Punycode
/// 编码**之后**再校验一次：`é` 一个字符会展开成多个 ASCII 字符，只在编码前
/// 检查会让匹配值超过数据库与协议侧的预期长度。
pub const MAX_EMAIL_LENGTH: usize = 254;

/// 一个已规范化的邮箱地址。
///
/// 不变量：`display` 与 `canonical` 由同一次 [`EmailAddress::parse`] 产出，
/// 二者的域名部分完全相同，只在本地部分的大小写上可能不同。
#[derive(Clone)]
pub struct EmailAddress {
    display: String,
    canonical: String,
    /// `canonical` 中 `@` 的字节下标，用来免分配地切出本地部分与域名。
    canonical_at: usize,
}

/// 相等性按**匹配值**判定，不比较展示值。
///
/// `==` 在这个类型上的语义是"是不是同一个邮箱"，而这正是匹配值的定义。若按全字段
/// 派生，`User@example.com` 与 `user@example.com` 会不相等——那恰好是本 Issue 要
/// 消除的那类假阴性，只是从数据库搬到了内存里。
///
/// 需要区分展示值时显式比较 [`EmailAddress::display`]。
impl PartialEq for EmailAddress {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for EmailAddress {}

/// 与 [`PartialEq`] 保持一致：相等的值必须有相同的哈希，否则放进 `HashMap`
/// 会同时命中"相等"和"不同桶"两种矛盾状态。
impl std::hash::Hash for EmailAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    #[error("email is empty")]
    Empty,
    #[error("email is longer than {MAX_EMAIL_LENGTH} characters")]
    TooLong,
    #[error("email contains whitespace or control characters")]
    ForbiddenCharacter,
    #[error("email must contain exactly one @")]
    MalformedStructure,
    #[error("email local part is empty")]
    EmptyLocalPart,
    #[error(
        "email local part must not start or end with a dot, and must not contain consecutive dots"
    )]
    InvalidLocalPart,
    #[error("email domain is not a valid IDNA domain name")]
    InvalidDomain,
}

impl EmailAddress {
    /// 规范化并校验一个原始输入。
    ///
    /// 判定顺序按"代价从低到高"排列：长度和字符集是 O(n) 且不分配，
    /// IDNA 处理要建缓冲区做 Unicode 映射。超长输入因此不会触发 UTS-46。
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EmailError::Empty);
        }
        if trimmed.chars().count() > MAX_EMAIL_LENGTH {
            return Err(EmailError::TooLong);
        }
        // 空白与控制字符在邮箱里没有合法位置（带引号的本地部分不在支持范围内），
        // 而它们进入日志、邮件头或 SQL 绑定参数都会造成解析歧义。
        if trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(EmailError::ForbiddenCharacter);
        }

        // 恰好一个 `@`：多个 `@` 的地址需要带引号的本地部分才合法，本项目不支持
        // 那种形态，按 `rsplit_once` 猜哪个是分隔符只会让边界更模糊。
        let mut parts = trimmed.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(EmailError::MalformedStructure);
        };
        if local.is_empty() {
            return Err(EmailError::EmptyLocalPart);
        }
        // RFC 5321 Dot-string 语法：`Atom *("." Atom)`，Atom 至少一个字符。
        // 前导、尾随或连续点号都要求出现空的 Atom，不属于任何合法 dot-string。
        // 这是准入校验而不是归一化：`a.b@` 与 `ab@` 的合并是 provider 特定语义
        // （见文件头注释），但畸形书写既违反协议，又会在折叠点号的 provider 上
        // 与受害者地址语义等价，成为账号混淆的种子（Issue #347）。
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(EmailError::InvalidLocalPart);
        }
        let domain = canonical_domain(domain)?;

        // Punycode 展开后重新校验长度，见 `MAX_EMAIL_LENGTH` 的注释。
        let display = format!("{local}@{domain}");
        if display.chars().count() > MAX_EMAIL_LENGTH {
            return Err(EmailError::TooLong);
        }
        let canonical = format!("{}@{domain}", local.to_ascii_lowercase());
        // 本地部分的 ASCII 小写不改变字节长度，`display` 的下标同样适用，
        // 但显式重算一次，免得以后本地部分策略变化时这里悄悄错位。
        let canonical_at = canonical
            .rfind('@')
            .expect("canonical form is built with an @");

        Ok(Self {
            display,
            canonical,
            canonical_at,
        })
    }

    /// 对外展示与外发邮件使用的值。
    pub fn display(&self) -> &str {
        &self.display
    }

    /// 唯一性与登录匹配使用的值，对应 `users.canonical_email`。
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// 匹配值的本地部分（已 ASCII 小写）。
    pub fn canonical_local_part(&self) -> &str {
        &self.canonical[..self.canonical_at]
    }

    /// 匹配值的域名部分（IDNA ASCII 形态）。展示值的域名与它逐字节相同。
    pub fn canonical_domain(&self) -> &str {
        &self.canonical[self.canonical_at + 1..]
    }

    /// 拆出两个字段，供仓储层直接绑定 SQL 参数。
    pub fn into_parts(self) -> (String, String) {
        (self.display, self.canonical)
    }

    pub fn into_display(self) -> String {
        self.display
    }

    pub fn into_canonical(self) -> String {
        self.canonical
    }
}

/// 域名的 UTS-46 规范化。
///
/// 独立公开是因为 `EmailPolicySetting` 的域名白名单必须用同一套规则算键：
/// 白名单里存 `éxample.com` 而邮箱匹配值里是 `xn--xample-9ua.com` 的话，
/// 策略永远不命中，等于白名单失效。
pub fn canonical_domain(domain: &str) -> Result<String, EmailError> {
    if domain.is_empty() {
        return Err(EmailError::InvalidDomain);
    }
    let ascii = Uts46::new()
        .to_ascii(
            domain.as_bytes(),
            AsciiDenyList::URL,
            Hyphens::Allow,
            DnsLength::Verify,
        )
        .map_err(|_| EmailError::InvalidDomain)?
        .into_owned();
    // 至少一个点：保留补丁前 `is_valid_email` 的边界，不放宽到单标签主机名。
    // 放在 IDNA 之后判定，因为 `xn--` 标签解码后仍然可能是单标签。
    if !ascii.contains('.') {
        return Err(EmailError::InvalidDomain);
    }
    Ok(ascii)
}

/// 输入是否是一个可规范化的邮箱。
///
/// 只在"只需要判定、不需要结果"的地方使用（例如 SMTP 发件人形如
/// `Name <a@b>` 的解析）。写路径必须持有 [`EmailAddress`]，不能只调这个。
pub fn is_valid_email(raw: &str) -> bool {
    EmailAddress::parse(raw).is_ok()
}

/// 邮箱是账号标识符，属于个人数据但不是凭据；Debug 保留两个值以便排查
/// "展示值对得上、匹配值对不上"这类规范化漂移。
impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailAddress")
            .field("display", &self.display)
            .field("canonical", &self.canonical)
            .finish()
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
