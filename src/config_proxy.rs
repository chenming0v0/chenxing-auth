use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use super::ConfigError;

/// 可信代理列表，用于从 `X-Forwarded-For` 解析真实客户端 IP（#111）。
///
/// 采用**精确 IP 列表**而不是 CIDR：项目没有 `ipnet` 之类的依赖，手写掩码比较会
/// 引入一段需要独立验证的位运算代码，而绝大多数部署只有 1~2 个固定的代理地址
/// （Nginx / Traefik sidecar、Ingress Service IP）。需要网段支持时再扩展这里，
/// 对调用方（`resolve_client_ip`）没有影响。
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    ips: Vec<IpAddr>,
}

impl TrustedProxies {
    /// 未配置任何可信代理。此时一律使用 TCP 对端地址，忽略 XFF。
    pub fn none() -> Self {
        Self { ips: Vec::new() }
    }

    pub fn from_ips(ips: Vec<IpAddr>) -> Self {
        Self { ips }
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }

    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// 解析真实客户端 IP。
    ///
    /// 判定顺序（任一条命中即返回，顺序本身就是安全边界）：
    /// 1. 未配置可信代理 → 对端地址。默认不信任任何转发头部。
    /// 2. 对端不在可信列表 → 对端地址。**这是防伪造的关键**：直连客户端可以
    ///    随手写一个 `X-Forwarded-For: 1.2.3.4`，采信它等于把限流 key 交给攻击者。
    /// 3. 对端可信 → 解析 XFF，见下。
    /// 4. 对端可信但无 XFF / XFF 不可解析 → 对端地址。
    ///
    /// ## 为什么从右往左扫描
    ///
    /// XFF 的语义是追加：`client, proxy1, proxy2`，最左是原始客户端，每一跳把
    /// 上一跳的地址追加到右侧。因此**只有右侧的条目是我们的基础设施写入的、可信的**；
    /// 左侧条目完全由客户端控制——攻击者请求时自带 `X-Forwarded-For: 9.9.9.9`，
    /// 代理会原样保留并在右边追加真实地址，最终变成 `9.9.9.9, <真实客户端>`。
    ///
    /// 取最左侧就会拿到 `9.9.9.9`，攻击者可以为每个请求伪造不同的值，从而绕过
    /// 按源限流（换一个假 IP 就是一份新额度）。
    ///
    /// 从右往左跳过所有**已知可信**的条目，第一个不可信的条目就是最后一个不受我们
    /// 控制的节点，也就是真实客户端。攻击者伪造的条目一定落在它左侧，永远不会被选中。
    pub fn resolve_client_ip(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<String> {
        let peer_ip = peer?.ip();
        if self.ips.is_empty() || !self.is_trusted(&peer_ip) {
            return Some(peer_ip.to_string());
        }
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .map(Self::parse_forwarded_chain)
            .unwrap_or_default();

        forwarded
            .iter()
            .rev()
            .find(|ip| !self.is_trusted(ip))
            // 整条链路都可信（罕见：只有内网多级代理，没有外部客户端条目）。
            // 此时最左侧是链路起点，且写入它的每一跳都受我们控制，可以采信。
            .or_else(|| forwarded.first())
            .map(IpAddr::to_string)
            .or(Some(peer_ip.to_string()))
    }

    /// 解析 XFF 为 IP 列表。无法解析的条目整体丢弃而不是跳过：混入 `unknown`、
    /// 端口后缀或废弃的 `for=` 语法时，链路位置已经不可靠，退回对端地址更安全。
    fn parse_forwarded_chain(value: &str) -> Vec<IpAddr> {
        let entries: Vec<&str> = value.split(',').map(str::trim).collect();
        let parsed: Vec<IpAddr> = entries
            .iter()
            .filter_map(|entry| entry.parse::<IpAddr>().ok())
            .collect();
        if parsed.len() == entries.len() {
            parsed
        } else {
            Vec::new()
        }
    }
}

/// 解析 `TRUSTED_PROXIES` 的取值。与环境无关，便于单测。
pub(super) fn parse_trusted_proxies(value: &str) -> Result<TrustedProxies, ConfigError> {
    if value.trim().is_empty() {
        return Ok(TrustedProxies::none());
    }
    let mut ips = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let ip = entry
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidValue("TRUSTED_PROXIES"))?;
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(TrustedProxies::from_ips(ips))
}

pub(super) fn trusted_proxies_from_env() -> Result<TrustedProxies, ConfigError> {
    match std::env::var("TRUSTED_PROXIES") {
        Ok(value) => parse_trusted_proxies(&value),
        Err(_) => Ok(TrustedProxies::none()),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn proxies(list: &[&str]) -> TrustedProxies {
        TrustedProxies::from_ips(list.iter().map(|ip| ip.parse().expect("test IP")).collect())
    }

    fn peer(address: &str) -> Option<SocketAddr> {
        Some(address.parse().expect("test socket address"))
    }

    fn headers_with_forwarded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(value).expect("test header"),
        );
        headers
    }

    #[test]
    fn parses_comma_separated_ipv4_and_ipv6() {
        let parsed = parse_trusted_proxies("10.0.0.5, ::1 ,192.168.1.1").expect("valid list");
        assert!(parsed.is_trusted(&"10.0.0.5".parse().unwrap()));
        assert!(parsed.is_trusted(&"::1".parse().unwrap()));
        assert!(parsed.is_trusted(&"192.168.1.1".parse().unwrap()));
        assert!(!parsed.is_trusted(&"203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn blank_value_means_no_trusted_proxy() {
        assert!(parse_trusted_proxies("").expect("blank").is_empty());
        assert!(parse_trusted_proxies("   ").expect("whitespace").is_empty());
    }

    /// CIDR 记法当前不支持，必须报错而不是被当成主机名静默忽略。
    #[test]
    fn rejects_invalid_entries_including_cidr() {
        for value in ["10.0.0.5,not-an-ip", "10.0.0.0/8", "10.0.0.5:8080"] {
            let error = parse_trusted_proxies(value).expect_err("must reject");
            assert_eq!(error, ConfigError::InvalidValue("TRUSTED_PROXIES"));
        }
    }

    #[test]
    fn missing_peer_yields_no_source_ip() {
        assert_eq!(
            proxies(&["10.0.0.5"]).resolve_client_ip(None, &HeaderMap::new()),
            None
        );
    }

    /// 未配置可信代理：XFF 一律忽略（默认安全）。
    #[test]
    fn unconfigured_proxies_ignore_forwarded_header() {
        let resolved = TrustedProxies::none()
            .resolve_client_ip(peer("203.0.113.42:443"), &headers_with_forwarded("198.51.100.7"));
        assert_eq!(resolved.as_deref(), Some("203.0.113.42"));
    }

    /// 伪造防护：对端不在可信列表时，XFF 完全不采信。
    #[test]
    fn untrusted_peer_cannot_spoof_the_forwarded_header() {
        let resolved = proxies(&["10.0.0.5"])
            .resolve_client_ip(peer("203.0.113.99:443"), &headers_with_forwarded("198.51.100.7"));
        assert_eq!(resolved.as_deref(), Some("203.0.113.99"));
    }

    #[test]
    fn single_proxy_resolves_the_client_entry() {
        let resolved = proxies(&["10.0.0.5"]).resolve_client_ip(
            peer("10.0.0.5:443"),
            &headers_with_forwarded("198.51.100.7, 10.0.0.5"),
        );
        assert_eq!(resolved.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn multi_hop_chain_skips_every_trusted_entry() {
        let resolved = proxies(&["10.0.0.5", "10.0.0.6"]).resolve_client_ip(
            peer("10.0.0.5:443"),
            &headers_with_forwarded("198.51.100.7, 10.0.0.6, 10.0.0.5"),
        );
        assert_eq!(resolved.as_deref(), Some("198.51.100.7"));
    }

    /// 攻击者自带 XFF，代理在右侧追加真实地址。从右往左扫描必须选中真实地址，
    /// 而不是伪造的最左条目——否则按源限流可以被无限换 key 绕过。
    #[test]
    fn client_supplied_prefix_is_never_selected() {
        let resolved = proxies(&["10.0.0.5"]).resolve_client_ip(
            peer("10.0.0.5:443"),
            &headers_with_forwarded("9.9.9.9, 203.0.113.77, 10.0.0.5"),
        );
        assert_eq!(resolved.as_deref(), Some("203.0.113.77"));
    }

    #[test]
    fn fully_trusted_chain_falls_back_to_the_leftmost_entry() {
        let resolved = proxies(&["10.0.0.5", "198.51.100.7"]).resolve_client_ip(
            peer("10.0.0.5:443"),
            &headers_with_forwarded("198.51.100.7, 10.0.0.5"),
        );
        assert_eq!(resolved.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn trusted_peer_without_forwarded_header_uses_the_peer() {
        let resolved =
            proxies(&["10.0.0.5"]).resolve_client_ip(peer("10.0.0.5:443"), &HeaderMap::new());
        assert_eq!(resolved.as_deref(), Some("10.0.0.5"));
    }

    /// 链路里出现无法解析的条目时整体丢弃，退回对端地址。
    #[test]
    fn malformed_chain_falls_back_to_the_peer() {
        for value in ["unknown, 10.0.0.5", "not-an-ip", "198.51.100.7:1234, 10.0.0.5"] {
            let resolved = proxies(&["10.0.0.5"])
                .resolve_client_ip(peer("10.0.0.5:443"), &headers_with_forwarded(value));
            assert_eq!(resolved.as_deref(), Some("10.0.0.5"), "value = {value}");
        }
    }

    #[test]
    fn ipv6_peer_and_chain_resolve() {
        let resolved = proxies(&["::1"]).resolve_client_ip(
            peer("[::1]:443"),
            &headers_with_forwarded("2001:db8::42, ::1"),
        );
        assert_eq!(resolved.as_deref(), Some("2001:db8::42"));
    }
}
