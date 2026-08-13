//! 外部 IdP 端点的出网地址边界（Issue #291）。
//!
//! 三个 provider 端点由管理员配置，服务端会主动向它们发起请求，因此它们是本服务
//! 唯一的「管理员可控出网目标」。仅校验 scheme 不足以构成边界：`https` 同样可以
//! 指向 `10.0.0.5`，域名也可以解析到 `169.254.169.254`。
//!
//! 这里定义两层，缺一层就留下绕过口：
//!
//! 1. **静态校验**（[`validate_endpoint_url`]）——保存和使用前对 URL 本身判定。
//!    它能拦下 IP 字面量，但对域名无能为力（域名此刻还不知道指向哪里）。
//! 2. **连接前筛查**（[`PublicEndpointResolver`]）——挂在 provider 专用 reqwest
//!    客户端的 DNS 解析器上，域名解析结果落在私网/特殊地址时直接让连接失败。
//!    放在解析器而不是「先解析再请求」的预检里，是为了不留下 DNS rebinding 的
//!    时间窗：这里返回的地址就是随后真正建连使用的地址。
//!
//! 第二层成立的前提是「解析器交出的地址就是建连地址」，而这一点由
//! [`super::http_client`] 里的 `no_proxy()` 保证：走 HTTP 代理时域名由代理解析、
//! 连接由代理建立，本层筛查的地址与实际连接目标无关（Issue #294）。
//!
//! 生产边界：远端端点必须是 `https`，且既不能是私网/链路本地/CGNAT/ULA 等特殊
//! 地址的字面量，也不能解析到这些地址。
//!
//! 开发例外：仅回环主机（`localhost`、`127.0.0.0/8`、`::1`）可用，且允许 `http`，
//! 用于本机联调外部 IdP。例外由 `OAUTH_PROVIDER_LOOPBACK_ENABLED` 显式开启
//! （Issue #343）：未开启时回环端点在任意环境一律拒绝，生产部署不会因为开发便利
//! 而出现「向本机服务泄露 client secret / 用户 access token」的出网路径。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use thiserror::Error;
use url::{Host, Url};

use super::domain::ProviderValidationError;

/// 端点出网边界策略。
///
/// 生产与开发只在一个维度上不同：是否允许回环例外。回环例外同时包含两层——
/// 静态校验放行回环主机（含明文 `http`），以及解析筛查放行 `localhost` 解析到
/// 回环地址。两者必须一起门控，否则只关静态层、解析层仍放行 `localhost`，
/// `https://localhost` 这类端点就会绕过生产边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointPolicy {
    /// 允许回环主机与明文 `http` 的开发例外，仅限本机联调。
    allow_loopback: bool,
}

impl EndpointPolicy {
    /// 生产边界：远端端点必须 `https` 且地址公网可路由，回环一律拒绝。
    pub const PRODUCTION: Self = Self {
        allow_loopback: false,
    };
    /// 开发例外：回环主机可用且允许明文 `http`（本机 IdP 通常没有可信证书）。
    pub const DEV_LOOPBACK: Self = Self {
        allow_loopback: true,
    };

    /// 由配置值构造：`OAUTH_PROVIDER_LOOPBACK_ENABLED` 为 `true` 时得到开发例外。
    pub fn new(allow_loopback: bool) -> Self {
        Self { allow_loopback }
    }

    pub fn allow_loopback(self) -> bool {
        self.allow_loopback
    }
}

/// 端点主机按出网风险分成三类，`validate_endpoint_url` 只需要对这三类表态。
#[derive(Debug, Clone, Copy)]
enum EndpointHostClass {
    /// 回环：仅在开发策略下放行的例外。
    Loopback,
    /// 公网可路由的 IP 字面量，或需要在连接前筛查解析结果的域名。
    Public,
    /// 私网、链路本地、CGNAT、ULA、组播、保留段等一律不可作为出网目标。
    Forbidden,
}

/// 解析结果筛查失败的原因。两种都折叠成「连接失败」，不回显给调用方。
#[derive(Debug, Error)]
pub enum EndpointAddressError {
    #[error("provider endpoint host could not be resolved")]
    Unresolved,
    #[error("provider endpoint host resolves to a non-public address")]
    NonPublicAddress,
}

/// 校验 provider 端点 URL 的形态与地址边界。
///
/// 除地址判定外还拒绝 URL 里的凭据和 fragment：两者都不属于服务端到服务端的
/// 端点，出现即说明配置来源不可信。
pub fn validate_endpoint_url(
    url: &Url,
    policy: EndpointPolicy,
) -> Result<(), ProviderValidationError> {
    // 形态先判：scheme、凭据、fragment 与地址空间无关，错在这里说明配置来源不可信。
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderValidationError::InvalidEndpoint);
    }
    let host = url.host().ok_or(ProviderValidationError::InvalidEndpoint)?;
    match classify_host(&host) {
        EndpointHostClass::Forbidden => Err(ProviderValidationError::PrivateEndpoint),
        // 开发例外（Issue #343 门控）：回环端点允许明文，本机 IdP 通常没有可信
        // 证书。未开启例外时回环与私网同等对待——本服务会向端点发送解密后的
        // client secret 和用户 access token，生产部署不允许这样的目标。
        EndpointHostClass::Loopback if policy.allow_loopback() => Ok(()),
        EndpointHostClass::Loopback => Err(ProviderValidationError::PrivateEndpoint),
        // 生产边界：远端端点必须 https。域名的实际指向由解析器筛查兜底。
        EndpointHostClass::Public if url.scheme() == "https" => Ok(()),
        EndpointHostClass::Public => Err(ProviderValidationError::InvalidEndpoint),
    }
}

fn classify_host(host: &Host<&str>) -> EndpointHostClass {
    match host {
        // RFC 6761：`localhost` 保证指向回环，是开发例外的唯一域名形态。
        // 其他域名（含 `*.localhost`）走 https + 解析筛查，不在静态层放行。
        Host::Domain(domain) if domain.eq_ignore_ascii_case("localhost") => {
            EndpointHostClass::Loopback
        }
        Host::Domain(_) => EndpointHostClass::Public,
        Host::Ipv4(address) => classify_address(IpAddr::V4(*address)),
        Host::Ipv6(address) => classify_address(IpAddr::V6(*address)),
    }
}

fn classify_address(address: IpAddr) -> EndpointHostClass {
    if address.is_loopback() {
        return EndpointHostClass::Loopback;
    }
    if is_public_endpoint_address(address) {
        EndpointHostClass::Public
    } else {
        EndpointHostClass::Forbidden
    }
}

/// 判断一个 IP 是否可以作为外部 IdP 的出网目标。
///
/// 只放行公网可路由的单播地址。回环在这里同样为 `false`——它是调用方按开发例外
/// 单独放行的，不属于「公网地址」。
pub fn is_public_endpoint_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    if address.is_unspecified()
        || address.is_loopback()
        // RFC 1918 私网。
        || address.is_private()
        // RFC 3927 链路本地，含 169.254.169.254 云元数据地址。
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        // RFC 5737 文档用地址。
        || address.is_documentation()
    {
        return false;
    }
    // 标准库的 is_shared / is_benchmarking / is_reserved 仍是 unstable，
    // 因此以下网段按八位组手写，不依赖不稳定 API。
    let [first, second, third, _] = address.octets();
    // 0.0.0.0/8 本网络。
    let this_network = first == 0;
    // RFC 6598 共享地址空间（CGNAT）100.64.0.0/10。
    let shared = first == 100 && (64..128).contains(&second);
    // RFC 6890 IETF 协议分配 192.0.0.0/24。
    let protocol_assignments = first == 192 && second == 0 && third == 0;
    // RFC 3068 6to4 中继任播 192.88.99.0/24（已废弃）。
    let relay_anycast = first == 192 && second == 88 && third == 99;
    // RFC 2544 基准测试 198.18.0.0/15。
    let benchmarking = first == 198 && (second == 18 || second == 19);
    // 240.0.0.0/4 保留段。
    let reserved = first >= 240;
    !(this_network || shared || protocol_assignments || relay_anycast || benchmarking || reserved)
}

/// RFC 4291 §2.4 全局单播前缀。IANA 目前只从这一段分配可路由的单播地址。
const GLOBAL_UNICAST: (u128, u32) = (0x2000_0000_0000_0000_0000_0000_0000_0000, 3);

/// 全局单播内部被特殊用途占用的前缀（IANA IPv6 Special-Purpose Address Registry）。
///
/// 只列 `2000::/3` 内部的例外。`2000::/3` 之外的一切——回环、ULA `fc00::/7`、
/// 链路本地 `fe80::/10`、站点本地 `fec0::/10`、RFC 6666 discard-only `100::/64`、
/// 组播 `ff00::/8` 以及全部未分配空间——由全局单播判定统一拒绝，不在这里重复。
const RESERVED_GLOBAL_UNICAST_PREFIXES: [(u128, u32); 5] = [
    // RFC 6890 IETF 协议分配 2001::/23。含 Teredo 2001::/32、基准测试 2001:2::/48、
    // AMT 2001:3::/32、ORCHID 2001:20::/28，逐个列出没有额外价值。
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
    // RFC 3849 文档用地址 2001:db8::/32。db8 > 01ff，不在上面的 /23 内，单列一行。
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
    // RFC 9637 文档用地址 3fff::/20。
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
    // RFC 9602 SRv6 SID 5f00::/16。
    (0x5f00_0000_0000_0000_0000_0000_0000_0000, 16),
    // RFC 3056 6to4 2002::/16。整段拒绝而不是按内嵌 IPv4 判定：RFC 7526 已废弃该机制，
    // 放行它只会多出一条把 IPv4 目标藏进 IPv6 字面量的路径。
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
];

/// IPv6 的判定方向与 IPv4 相反：先取出内嵌 IPv4，再只放行全局单播 `2000::/3`
/// 里未被特殊用途占用的部分。
///
/// 用 allowlist 而不是「逐段排除私网」是因为 IPv6 地址空间绝大部分尚未分配。
/// 逐段排除意味着每次 IANA 新分配一段特殊用途前缀，这里就默认放行一段——
/// `fec0::/10` 站点本地就是这样漏掉的（Issue #294）。只认 `2000::/3` 之后，
/// 未分配空间天然是拒绝的，新增例外只需要往上面那张表里加一行。
fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() {
        return false;
    }
    // 内嵌 IPv4 的形态必须按内层地址判定，否则 `::ffff:10.0.0.1` 之类是直接绕过口。
    // 必须放在全局单播判定之前：这些前缀都落在 `2000::/3` 之外，否则会被整段拒绝，
    // 而 NAT64 部署（`64:ff9b::/96`）的公网目标是需要继续可用的。内层地址的组播、
    // 私网等形态由 `is_public_ipv4` 覆盖。
    if let Some(embedded) = embedded_ipv4(address) {
        return is_public_ipv4(embedded);
    }
    let bits = u128::from_be_bytes(address.octets());
    if !matches_prefix(bits, GLOBAL_UNICAST) {
        return false;
    }
    !RESERVED_GLOBAL_UNICAST_PREFIXES
        .iter()
        .any(|prefix| matches_prefix(bits, *prefix))
}

/// 判断地址是否落在 `prefix/length` 内。`length` 恒在 1..=128，由上面的常量保证。
fn matches_prefix(bits: u128, (prefix, length): (u128, u32)) -> bool {
    let mask = u128::MAX << (128 - length);
    bits & mask == prefix & mask
}

/// 取出 IPv6 地址里内嵌的 IPv4 地址。
///
/// 覆盖三种会把 IPv4 目标藏进 IPv6 字面量的形态：IPv4-mapped `::ffff:0:0/96`、
/// 已废弃的 IPv4-compatible `::/96` 和 RFC 6052 NAT64 `64:ff9b::/96`。三者都落在
/// `2000::/3` 之外，因此必须在全局单播判定之前按内层地址判定——NAT64 部署里所有
/// 目标都是合成地址，整段拒绝会让这类部署完全不可用。
///
/// 6to4（`2002::/16`）不在这里：它落在 `2000::/3` 内，且 RFC 7526 已废弃该机制，
/// 由 [`RESERVED_GLOBAL_UNICAST_PREFIXES`] 整段拒绝，不再按内嵌 IPv4 放行。
///
/// 调用方必须先排除 `::` 与 `::1`，否则会被当成 `::/96` 内嵌。
fn embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = address.segments();
    let nat64 = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0;
    let compatible_or_mapped = segments[..5].iter().all(|segment| *segment == 0)
        && (segments[5] == 0 || segments[5] == 0xffff);
    if nat64 || compatible_or_mapped {
        return Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        ));
    }
    None
}

/// 筛查一次 DNS 解析的结果。
///
/// fail-closed：只要有一个地址落在禁止空间就整批拒绝，而不是过滤后交出剩余地址。
/// 过滤会让「同时返回公网和私网 A 记录」的域名仍然可用，攻击者只需让客户端在
/// 重试时命中私网记录。整批拒绝把这条路彻底关掉。
pub fn screen_resolved_addresses(
    host: &str,
    addresses: Vec<SocketAddr>,
    policy: EndpointPolicy,
) -> Result<Vec<SocketAddr>, EndpointAddressError> {
    if addresses.is_empty() {
        return Err(EndpointAddressError::Unresolved);
    }
    // 回环开发例外只对 `localhost` 生效，且必须由策略显式开启（Issue #343）：
    // 生产策略下任何解析到回环的结果都是绕过尝试；其他域名解析到回环同理。
    let loopback_allowed = policy.allow_loopback() && host.eq_ignore_ascii_case("localhost");
    let all_allowed = addresses.iter().all(|address| {
        let ip = address.ip();
        if ip.is_loopback() {
            loopback_allowed
        } else {
            is_public_endpoint_address(ip)
        }
    });
    if all_allowed {
        Ok(addresses)
    } else {
        Err(EndpointAddressError::NonPublicAddress)
    }
}

/// provider 出网客户端专用的 DNS 解析器：解析结果不通过筛查就不建连。
///
/// IP 字面量不经过这里（reqwest 直接连），由 [`validate_endpoint_url`] 覆盖。
/// 回环放行与否由构造时给定的 [`EndpointPolicy`] 决定，生产策略下 `localhost`
/// 解析到回环同样拒绝。
#[derive(Debug, Clone, Copy)]
pub struct PublicEndpointResolver {
    policy: EndpointPolicy,
}

impl PublicEndpointResolver {
    pub fn new(policy: EndpointPolicy) -> Self {
        Self { policy }
    }
}

impl Resolve for PublicEndpointResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let policy = self.policy;
        Box::pin(async move {
            // 端口 0 只用于触发解析，实际端口由 reqwest 按 URL 覆盖。
            let resolved = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| EndpointAddressError::Unresolved);
            let screened = resolved
                .and_then(|addresses| screen_resolved_addresses(&host, addresses.collect(), policy))
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })?;
            Ok(Box::new(screened.into_iter()) as Addrs)
        })
    }
}
