//! Issue #291：provider 端点的出网地址边界。
//!
//! 两层校验各测一层：
//!
//! - [`validate_endpoint_url`] 对 URL 本身判定，拦下 IP 字面量与远端明文。
//! - [`screen_resolved_addresses`] 对 DNS 解析结果判定，拦下「域名解析到私网」的
//!   盲 SSRF——这一层是静态校验看不见的部分。
//!
//! 这些用例不连数据库、不发真实请求，纯粹钉住策略表。

use std::net::{IpAddr, SocketAddr};

use chenxing_auth::oauth::providers::{
    domain::{ClientAuthMethod, ProviderInput, ProviderValidationError},
    endpoint_policy::{
        EndpointAddressError, is_public_endpoint_address, screen_resolved_addresses,
        validate_endpoint_url,
    },
};
use url::Url;

fn endpoint(value: &str) -> Result<(), ProviderValidationError> {
    validate_endpoint_url(&Url::parse(value).expect("endpoint URL"))
}

fn provider_input(authorization_endpoint: &str) -> ProviderInput {
    ProviderInput {
        name: "企业 SSO".to_owned(),
        slug: "enterprise-sso".to_owned(),
        authorization_endpoint: authorization_endpoint.to_owned(),
        token_endpoint: "https://sso.example.com/oauth/token".to_owned(),
        userinfo_endpoint: "https://sso.example.com/oauth/userinfo".to_owned(),
        client_id: "client-id".to_owned(),
        client_secret: Some("client-secret".to_owned()),
        scopes: vec!["openid".to_owned()],
        subject_claim: "sub".to_owned(),
        email_claim: "email".to_owned(),
        name_claim: None,
        email_verified_claim: Some("email_verified".to_owned()),
        client_auth_method: ClientAuthMethod::Basic,
        pkce_enabled: true,
    }
}

fn addresses(values: &[&str]) -> Vec<SocketAddr> {
    values
        .iter()
        .map(|value| {
            let address: IpAddr = value.parse().expect("IP address");
            SocketAddr::new(address, 443)
        })
        .collect()
}

/// 核心回归：`https` 过去对任意主机放行，私网 IP 字面量可以直接存进配置。
#[test]
fn https_endpoint_rejects_private_and_special_address_literals() {
    for value in [
        // RFC 1918
        "https://10.0.0.5/oauth/token",
        "https://172.16.0.1/oauth/token",
        "https://192.168.1.1/oauth/token",
        // RFC 3927 链路本地，含云元数据地址
        "https://169.254.169.254/latest/meta-data/",
        // RFC 6598 CGNAT
        "https://100.64.0.1/oauth/token",
        // RFC 2544 基准测试
        "https://198.18.0.1/oauth/token",
        // 0.0.0.0/8 与 240.0.0.0/4 保留段
        "https://0.0.0.1/oauth/token",
        "https://255.255.255.255/oauth/token",
        // RFC 4193 ULA 与 RFC 4291 链路本地单播
        "https://[fc00::1]/oauth/token",
        "https://[fe80::1]/oauth/token",
        // IPv4-mapped / NAT64 / 6to4 都不能成为绕过口
        "https://[::ffff:10.0.0.1]/oauth/token",
        "https://[64:ff9b::a00:1]/oauth/token",
        "https://[2002:0a00:0001::]/oauth/token",
    ] {
        assert_eq!(
            endpoint(value).expect_err(value),
            ProviderValidationError::PrivateEndpoint,
            "{value} 必须按非公网地址拒绝"
        );
    }
}

/// 私网端点连保存都不允许，而不是等到运行时才失败。
#[test]
fn provider_input_rejects_private_https_endpoint() {
    assert_eq!(
        provider_input("https://10.0.0.5/oauth/authorize")
            .validate()
            .expect_err("private https endpoint"),
        ProviderValidationError::PrivateEndpoint
    );
}

/// 合法的公有端点必须继续可用，否则这条边界就是在制造故障。
#[test]
fn https_endpoint_accepts_public_hosts() {
    for value in [
        "https://sso.example.com/oauth/token",
        "https://93.184.216.34/oauth/token",
        "https://[2606:4700:4700::1111]/oauth/token",
    ] {
        endpoint(value).unwrap_or_else(|error| panic!("{value} 应放行，却得到 {error}"));
    }
    provider_input("https://sso.example.com/oauth/authorize")
        .validate()
        .expect("public https provider");
}

/// 保留的开发例外：回环主机可用，且允许 http（本机 IdP 通常没有可信证书）。
#[test]
fn loopback_endpoint_remains_a_development_exception() {
    for value in [
        "http://localhost:8080/oauth/token",
        "http://127.0.0.1:8080/oauth/token",
        "http://[::1]:8080/oauth/token",
        "https://localhost:8443/oauth/token",
        "https://127.0.0.1:8443/oauth/token",
    ] {
        endpoint(value).unwrap_or_else(|error| panic!("{value} 应放行，却得到 {error}"));
    }
}

/// 生产边界：远端主机一律要求 https，形态错误仍然是 `InvalidEndpoint`。
#[test]
fn remote_http_and_malformed_endpoints_stay_rejected() {
    for value in [
        "http://sso.example.com/oauth/token",
        "http://93.184.216.34/oauth/token",
        // `*.localhost` 不在静态回环例外内，走 https + 解析筛查。
        "http://app.localhost/oauth/token",
        "ftp://sso.example.com/oauth/token",
        "https://user:secret@sso.example.com/oauth/token",
        "https://sso.example.com/oauth/token#fragment",
    ] {
        assert_eq!(
            endpoint(value).expect_err(value),
            ProviderValidationError::InvalidEndpoint,
            "{value} 必须按形态非法拒绝"
        );
    }
}

/// 盲 SSRF 的实际入口：域名形态完全合法，指向由 DNS 决定。
#[test]
fn resolution_screening_rejects_private_answers() {
    for value in ["10.0.0.5", "169.254.169.254", "192.168.1.1", "fc00::1"] {
        let error = screen_resolved_addresses("internal.corp.example", addresses(&[value]))
            .expect_err("private resolution");
        assert!(
            matches!(error, EndpointAddressError::NonPublicAddress),
            "{value} 必须按非公网解析结果拒绝，却得到 {error}"
        );
    }
}

/// 回环例外只认 `localhost`：任何其他域名解析到回环都是绕过尝试。
#[test]
fn resolution_screening_confines_loopback_to_localhost() {
    screen_resolved_addresses("localhost", addresses(&["127.0.0.1", "::1"]))
        .expect("localhost resolves to loopback");

    let error = screen_resolved_addresses("rebind.example.com", addresses(&["127.0.0.1"]))
        .expect_err("loopback resolution for a public domain");
    assert!(matches!(error, EndpointAddressError::NonPublicAddress));
}

/// fail-closed：混合答案整批拒绝，否则重试就能命中私网记录。
#[test]
fn resolution_screening_rejects_mixed_answers_and_empty_results() {
    let mixed = addresses(&["93.184.216.34", "10.0.0.5"]);
    let error =
        screen_resolved_addresses("split.example.com", mixed).expect_err("mixed resolution");
    assert!(matches!(error, EndpointAddressError::NonPublicAddress));

    let error =
        screen_resolved_addresses("missing.example.com", Vec::new()).expect_err("empty resolution");
    assert!(matches!(error, EndpointAddressError::Unresolved));
}

/// 公有解析结果照常放行。
#[test]
fn resolution_screening_accepts_public_answers() {
    let resolved = addresses(&["93.184.216.34", "2606:4700:4700::1111"]);
    assert_eq!(
        screen_resolved_addresses("sso.example.com", resolved.clone()).expect("public resolution"),
        resolved
    );
}

/// 地址分类本身的边界，避免后续改动把某个网段悄悄放回去。
#[test]
fn address_classification_marks_only_public_unicast_as_public() {
    for value in ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"] {
        assert!(
            is_public_endpoint_address(value.parse().expect("IP address")),
            "{value} 应判为公网"
        );
    }
    for value in [
        "127.0.0.1",
        "::1",
        "10.0.0.5",
        "100.127.255.255",
        "169.254.169.254",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.19.0.1",
        "224.0.0.1",
        "2001:db8::1",
        "100::1",
        "ff02::1",
    ] {
        assert!(
            !is_public_endpoint_address(value.parse().expect("IP address")),
            "{value} 不应判为公网"
        );
    }
}
