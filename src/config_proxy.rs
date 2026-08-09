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
    pub fn resolve_client_ip(
        &self,
        peer: Option<SocketAddr>,
        headers: &HeaderMap,
    ) -> Option<String> {
        let peer_ip = peer?.ip();
        if self.ips.is_empty() || !self.is_trusted(&peer_ip) {
            return Some(peer_ip.to_string());
        }
        let forwarded = Self::forwarded_chain(headers);

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

    /// 把**所有** `X-Forwarded-For` 头部行按线序拼成一条链路并解析为 IP 列表。
    ///
    /// HTTP 允许同名头部重复出现，其语义等价于按接收顺序用逗号拼接成单行
    /// （RFC 9110 §5.3）。只读第一行是可伪造的（#269）：攻击者发送
    /// `X-Forwarded-For: 9.9.9.9` 后，Nginx 之类的代理若以追加新行的方式记录
    /// 转发链，真实客户端地址就落在第二行，第一行整行由攻击者控制。此时
    /// 「从右往左扫描」只能看到伪造值，选中的就是伪造 IP，按源限流形同虚设。
    /// 因此必须先按线序合并再扫描，让真实条目始终位于伪造条目的右侧。
    ///
    /// 任一行、任一条目无法解析（`unknown`、端口后缀、废弃的 `for=` 语法、
    /// 非 ASCII 字节）时整条链路丢弃而不是跳过：链路位置已经不可靠，
    /// 让调用方 fail-safe 退回对端地址更安全。
    fn forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
        let mut chain = Vec::new();
        for value in headers.get_all("x-forwarded-for") {
            let Ok(text) = value.to_str() else {
                return Vec::new();
            };
            for entry in text.split(',') {
                let Ok(ip) = entry.trim().parse::<IpAddr>() else {
                    return Vec::new();
                };
                chain.push(ip);
            }
        }
        chain
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
#[path = "config_proxy_tests.rs"]
mod tests;
