//! 单元测试：`TRUSTED_PROXIES` 解析与 `X-Forwarded-For` 客户端 IP 判定。
//!
//! 重点覆盖三类安全边界：
//! 1. 对端不可信时完全忽略 XFF（防伪造）
//! 2. 多行 XFF 必须按线序合并后再从右往左扫描（#269）
//! 3. 任一行、任一条目畸形时 fail-safe 退回对端地址

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

/// 多行同名头部：`append` 保持接收顺序，与代理真实写入顺序一致。
fn headers_with_forwarded_lines(lines: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_str(line).expect("test header"),
        );
    }
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
    let resolved = TrustedProxies::none().resolve_client_ip(
        peer("203.0.113.42:443"),
        &headers_with_forwarded("198.51.100.7"),
    );
    assert_eq!(resolved.as_deref(), Some("203.0.113.42"));
}

/// 伪造防护：对端不在可信列表时，XFF 完全不采信。
#[test]
fn untrusted_peer_cannot_spoof_the_forwarded_header() {
    let resolved = proxies(&["10.0.0.5"]).resolve_client_ip(
        peer("203.0.113.99:443"),
        &headers_with_forwarded("198.51.100.7"),
    );
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
    for value in [
        "unknown, 10.0.0.5",
        "not-an-ip",
        "198.51.100.7:1234, 10.0.0.5",
    ] {
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

/// #269 的核心回归：攻击者发一行 `X-Forwarded-For: 9.9.9.9`，代理把真实链路
/// 追加成第二行。只读第一行会选中 `9.9.9.9`；按线序合并后真实客户端条目位于
/// 伪造条目右侧，必须选中它。
#[test]
fn multiple_header_lines_are_merged_in_wire_order() {
    let resolved = proxies(&["10.0.0.5"]).resolve_client_ip(
        peer("10.0.0.5:443"),
        &headers_with_forwarded_lines(&["9.9.9.9", "203.0.113.77, 10.0.0.5"]),
    );
    assert_eq!(resolved.as_deref(), Some("203.0.113.77"));
}

/// 多行拆分与单行逗号拼接必须等价：合并后的链路只由线序决定，与代理选择
/// 「追加到同一行」还是「新起一行」无关。
#[test]
fn split_lines_and_single_line_resolve_identically() {
    let single = proxies(&["10.0.0.5", "10.0.0.6"]).resolve_client_ip(
        peer("10.0.0.5:443"),
        &headers_with_forwarded("9.9.9.9, 203.0.113.77, 10.0.0.6, 10.0.0.5"),
    );
    let split = proxies(&["10.0.0.5", "10.0.0.6"]).resolve_client_ip(
        peer("10.0.0.5:443"),
        &headers_with_forwarded_lines(&["9.9.9.9", "203.0.113.77, 10.0.0.6", "10.0.0.5"]),
    );
    assert_eq!(single.as_deref(), Some("203.0.113.77"));
    assert_eq!(split, single);
}

/// 每一跳各写一行、全链路可信：合并后最左侧仍是链路起点。
#[test]
fn fully_trusted_multi_line_chain_falls_back_to_the_leftmost_entry() {
    let resolved = proxies(&["10.0.0.5", "10.0.0.6", "198.51.100.7"]).resolve_client_ip(
        peer("10.0.0.5:443"),
        &headers_with_forwarded_lines(&["198.51.100.7", "10.0.0.6", "10.0.0.5"]),
    );
    assert_eq!(resolved.as_deref(), Some("198.51.100.7"));
}

/// 任一行畸形都让整条链路作废：否则攻击者可以用一行垃圾值截断解析，
/// 把选中位置挪到自己控制的条目上。位置不可靠时只能退回对端地址。
#[test]
fn malformed_entry_in_any_line_falls_back_to_the_peer() {
    let cases: [&[&str]; 4] = [
        // 首行畸形
        &["unknown", "203.0.113.77, 10.0.0.5"],
        // 中间行畸形
        &["9.9.9.9", "not-an-ip", "10.0.0.5"],
        // 末行畸形（带端口后缀）
        &["203.0.113.77", "10.0.0.5:1234"],
        // 空行：逗号切分后得到空条目，同样不可解析
        &["203.0.113.77, 10.0.0.5", ""],
    ];
    for lines in cases {
        let resolved = proxies(&["10.0.0.5"])
            .resolve_client_ip(peer("10.0.0.5:443"), &headers_with_forwarded_lines(lines));
        assert_eq!(resolved.as_deref(), Some("10.0.0.5"), "lines = {lines:?}");
    }
}

/// 非 UTF-8 头部（obs-text 字节合法但不是文本）同样走 fail-safe 分支。
#[test]
fn non_utf8_header_line_falls_back_to_the_peer() {
    let mut headers = headers_with_forwarded("203.0.113.77, 10.0.0.5");
    headers.append(
        "x-forwarded-for",
        HeaderValue::from_bytes(&[0xff, 0xfe]).expect("obs-text header value"),
    );
    let resolved = proxies(&["10.0.0.5"]).resolve_client_ip(peer("10.0.0.5:443"), &headers);
    assert_eq!(resolved.as_deref(), Some("10.0.0.5"));
}
