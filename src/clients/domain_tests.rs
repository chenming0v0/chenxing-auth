use super::*;

#[test]
fn registration_defaults_do_not_grant_legacy_cltermux_scope() {
    assert_eq!(DEFAULT_REGISTRATION_SCOPES, &["openid", "profile", "email"]);
    assert!(!DEFAULT_REGISTRATION_SCOPES.contains(&"cltermux:access"));
    assert_eq!(
        IMPLICIT_RUNTIME_SCOPE_UPPER_BOUND,
        &["openid", "profile", "email", "cltermux:access"]
    );
    assert_eq!(DEFAULT_ALLOWED_SCOPES, IMPLICIT_RUNTIME_SCOPE_UPPER_BOUND);
    assert!(
        ClientRegistrationLimits::default()
            .allowed_scopes
            .iter()
            .any(|scope| scope == "cltermux:access")
    );
}

/// 辅助函数：直接校验单个 redirect URI，返回归一化后的结果
fn validate_uri(uri: &str) -> Result<String, ClientRegistrationError> {
    validate_redirect_uri(uri.to_owned(), &ClientRegistrationLimits::default())
}

// ========== Issue #68: URL 归一化 ==========

#[test]
fn redirect_uri_normalizes_bare_origin_adds_trailing_slash() {
    // https://example.com 没有显式路径，归一化补全 trailing slash
    assert_eq!(
        validate_uri("https://example.com").unwrap(),
        "https://example.com/"
    );
}

#[test]
fn redirect_uri_normalizes_removes_default_https_port() {
    // https:443 是默认端口，归一化时去除
    assert_eq!(
        validate_uri("https://example.com:443/cb").unwrap(),
        "https://example.com/cb"
    );
}

#[test]
fn redirect_uri_with_explicit_path_unchanged() {
    // 显式路径的 URI 归一化后保持不变
    assert_eq!(
        validate_uri("https://example.com/oauth/callback").unwrap(),
        "https://example.com/oauth/callback"
    );
}

// ========== Issue #69: RFC 8252 回环地址放开 ==========

#[test]
fn redirect_uri_accepts_loopback_ipv4_http() {
    // RFC 8252 §7.3：原生/CLI 客户端可使用回环 HTTP
    assert_eq!(
        validate_uri("http://127.0.0.1:8080/cb").unwrap(),
        "http://127.0.0.1:8080/cb"
    );
}

#[test]
fn redirect_uri_accepts_loopback_ipv6_http() {
    // IPv6 回环地址 ::1
    assert_eq!(
        validate_uri("http://[::1]:8080/cb").unwrap(),
        "http://[::1]:8080/cb"
    );
}

#[test]
fn redirect_uri_accepts_any_loopback_ipv4() {
    // 整个 127.0.0.0/8 段均为回环，is_loopback() 正确处理
    assert_eq!(
        validate_uri("http://127.0.0.2/cb").unwrap(),
        "http://127.0.0.2/cb"
    );
    assert_eq!(
        validate_uri("http://127.255.255.255/cb").unwrap(),
        "http://127.255.255.255/cb"
    );
}

#[test]
fn redirect_uri_rejects_localhost_domain_http() {
    // RFC 8252 §8.3：明确排除 localhost 域名，只接受字面 IP
    // localhost 可能被 DNS 劫持或解析到非回环地址
    assert_eq!(
        validate_uri("http://localhost:8080/cb").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

#[test]
fn redirect_uri_rejects_non_loopback_http() {
    // 非回环地址的 HTTP 一律拒绝
    assert_eq!(
        validate_uri("http://example.com/cb").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

#[test]
fn redirect_uri_rejects_non_loopback_ipv4_http() {
    // 10.0.0.1 是私有地址但不是回环
    assert_eq!(
        validate_uri("http://10.0.0.1/cb").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

// ========== 危险 scheme 拒绝 ==========

#[test]
fn redirect_uri_rejects_javascript_scheme() {
    // javascript: 会被 url crate 解析成功，但 scheme 非 https/http → InsecureRedirectUri
    assert_eq!(
        validate_uri("javascript:alert(1)").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

#[test]
fn redirect_uri_rejects_data_scheme() {
    assert_eq!(
        validate_uri("data:text/html,<script>alert(1)</script>").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

#[test]
fn redirect_uri_rejects_custom_scheme() {
    // 自定义 scheme（如移动端 Deep Link）暂不支持
    assert_eq!(
        validate_uri("myapp://callback").unwrap_err(),
        ClientRegistrationError::InsecureRedirectUri,
    );
}

// ========== OAuth 2.0 协议约束 ==========

#[test]
fn redirect_uri_rejects_fragment() {
    // RFC 6749 §3.1.2：redirect_uri 不得含 fragment
    assert_eq!(
        validate_uri("https://example.com/cb#section").unwrap_err(),
        ClientRegistrationError::InvalidRedirectUri,
    );
}

#[test]
fn redirect_uri_rejects_userinfo() {
    // 已有测试覆盖 (tests/client_domain.rs)，此处确保回归
    assert_eq!(
        validate_uri("https://user:pass@example.com/cb").unwrap_err(),
        ClientRegistrationError::InvalidRedirectUri,
    );
}
