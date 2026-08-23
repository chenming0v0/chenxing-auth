use chenxing_auth::admin::AdminAuthenticator;

#[test]
fn admin_authenticator_accepts_only_configured_token() {
    let authenticator = AdminAuthenticator::new("admin-secret".to_owned());

    assert!(authenticator.is_valid("admin-secret"));
    assert!(!authenticator.is_valid("wrong-secret"));
}

#[test]
fn admin_authenticator_rejects_empty_configuration() {
    let authenticator = AdminAuthenticator::new(String::new());

    assert!(!authenticator.is_valid(""));
    assert!(!authenticator.is_valid("anything"));
}

#[test]
fn admin_authenticator_rejects_tokens_of_different_length() {
    // 回归 #71：修复前 is_valid 会先短路比较长度，攻击者可通过时序差异
    // 枚举出正确令牌的长度。现在长短不一的候选令牌都要走完整 HMAC 比较路径。
    let authenticator = AdminAuthenticator::new("admin-secret".to_owned());

    assert!(!authenticator.is_valid("admin"));
    assert!(!authenticator.is_valid("admin-secret-extra-suffix"));
    assert!(!authenticator.is_valid(""));
    assert!(!authenticator.is_valid("a"));
}

#[test]
fn admin_authenticator_instances_use_independent_mac_keys() {
    // 内部 MAC key 是每个实例随机生成的，不能影响比较结果的正确性。
    let first = AdminAuthenticator::new("admin-secret".to_owned());
    let second = AdminAuthenticator::new("admin-secret".to_owned());

    assert!(first.is_valid("admin-secret"));
    assert!(second.is_valid("admin-secret"));
    assert!(!first.is_valid("admin-secre"));
    assert!(!second.is_valid("admin-secretx"));
}

#[test]
fn admin_authenticator_clone_preserves_validation() {
    // AppState 会克隆 AdminAuthenticator，克隆体必须沿用同一 mac_key 与令牌。
    let authenticator = AdminAuthenticator::new("admin-secret".to_owned());
    let cloned = authenticator.clone();

    assert!(cloned.is_valid("admin-secret"));
    assert!(!cloned.is_valid("wrong"));
}
