use super::*;

fn config_with_session_ttl(session_ttl_seconds: u64) -> Config {
    Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        session_ttl_seconds,
    )
    .expect("valid test configuration")
}

/// #112 的核心断言：拉长浏览器会话 TTL 不得同时拉长无状态 access token 的窗口。
/// 两者的安全权衡完全不同——会话有 HttpOnly、CSRF 绑定且可即时撤销，
/// access token 是 JWT，撤销只在 userinfo 端点生效。
#[test]
fn token_ttls_are_independent_of_the_session_ttl() {
    let week = 604_800;
    let config = config_with_session_ttl(week);

    assert_eq!(config.session_ttl_seconds, week);
    assert_eq!(
        config.session_idle_timeout_seconds,
        DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS
    );
    assert_eq!(
        config.session_max_concurrent_sessions,
        DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS
    );
    assert_eq!(config.access_token_ttl_seconds, 3600);
    assert_eq!(config.id_token_ttl_seconds, 3600);
    assert_ne!(config.access_token_ttl_seconds, config.session_ttl_seconds);
}

/// 会话 TTL 取任何值都不影响令牌 TTL（回归保护：防止再次被同一个字段驱动）。
#[test]
fn changing_the_session_ttl_never_moves_the_token_ttls() {
    for session_ttl in [60, 3_600, 86_400, 604_800] {
        let config = config_with_session_ttl(session_ttl);
        assert_eq!(config.session_ttl_seconds, session_ttl);
        assert_eq!(config.access_token_ttl_seconds, 3600);
        assert_eq!(config.id_token_ttl_seconds, 3600);
    }
}

/// 测试构造函数不接受新增字段，必须自带安全默认值（`from_values*` 签名保持不变）。
#[test]
fn test_constructors_default_to_safe_values() {
    let config = config_with_session_ttl(3600);

    assert!(config.cookie_secure);
    // 未配置可信代理：忽略 XFF，等价于升级前的行为。
    assert!(config.trusted_proxies.is_empty());
    assert_eq!(config.security_limits, SecurityLimits::default());
    // #303：静态根默认是相对路径，绝不是空值——空值会在启动期被拒绝。
    assert_eq!(config.web_dist_dir, crate::web_dist::DEFAULT_WEB_DIST_DIR);
    assert!(!config.web_dist_dir.trim().is_empty());
    // Issue #316：跨实例时钟偏差容忍默认开启（多实例部署的安全默认），
    // 且不改变保留窗口本身的默认值。
    assert_eq!(
        config.key_rotation_skew_allowance_seconds,
        DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS
    );
}

#[test]
fn session_ttl_of_zero_is_still_rejected() {
    let error = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        0,
    )
    .expect_err("zero session TTL must be rejected");
    assert_eq!(error, ConfigError::InvalidValue("SESSION_TTL_SECONDS"));
}

/// #365：会话 TTL 有上界。u64::MAX 秒的绝对 TTL 会原样送进 Redis
/// `SET ... EX`（`SessionStore::redis_ttl_seconds`），Redis 整数上限是 i64，
/// 超限即每次登录/会话写入失败；必须在启动校验阶段拒绝，而不是等错误指向 Redis。
#[test]
fn session_ttl_beyond_the_upper_bound_is_rejected() {
    for session_ttl in [MAX_SESSION_TTL_SECONDS + 1, u64::MAX] {
        let error = Config::from_values(
            "127.0.0.1".to_owned(),
            3000,
            "postgres://localhost/chenxing_auth".to_owned(),
            "redis://localhost".to_owned(),
            session_ttl,
        )
        .expect_err("session TTL beyond the upper bound must be rejected");
        assert_eq!(error, ConfigError::InvalidValue("SESSION_TTL_SECONDS"));
    }
}

#[test]
fn insecure_cookies_are_allowed_only_for_loopback_http() {
    let mut config = config_with_session_ttl(3600);
    config.cookie_secure = false;
    assert!(config.validate_cookie_security().is_ok());

    config.issuer_url = "https://auth.example.com".to_owned();
    assert_eq!(
        config.validate_cookie_security(),
        Err(ConfigError::InvalidValue("COOKIE_SECURE"))
    );

    config.issuer_url = "http://auth.example.com".to_owned();
    assert_eq!(
        config.validate_cookie_security(),
        Err(ConfigError::InvalidValue("COOKIE_SECURE"))
    );
}
