//! `consent_cache` 的单元测试（Issue #276）。
//!
//! 拆成独立文件而不是内联 `mod tests`：`consent_cache.rs` 的注释密度较高
//! （设计取舍需要写清楚），内联测试会把它推过 300 行的弱警告线。
//! 与 `keys_tests.rs` / `handlers_tests.rs` 的既有做法一致。

use super::{
    ACTIVE_MARKER, CONSENT_STATE_CACHE_ONLY_TTL_SECONDS, CONSENT_STATE_CACHE_TTL_SECONDS,
    CachedConsentState, ConsentStateCache, REVOKED_MARKER,
};
use crate::oauth::refresh::REFRESH_TOKEN_ABSOLUTE_TTL_DAYS;

#[test]
fn cached_state_parses_versioned_markers() {
    assert_eq!(
        CachedConsentState::parse(&format!("2:{REVOKED_MARKER}")),
        Some(CachedConsentState::Revoked)
    );
    assert_eq!(
        CachedConsentState::parse(&format!("3:{ACTIVE_MARKER}")),
        Some(CachedConsentState::Active)
    );
}

#[test]
fn unparseable_cached_values_are_treated_as_a_miss() {
    // 旧格式（Issue #276 之前的无版本值 "1"）和脏值都必须回落到权威源，
    // 而不是被猜成某一侧结论。
    for raw in ["1", "", "2:x", ":r", "0:r", "-1:r", "abc:r", "abc"] {
        assert_eq!(CachedConsentState::parse(raw), None, "{raw:?}");
    }
}

#[test]
fn cache_key_is_bound_to_both_user_and_client() {
    let base = ConsentStateCache::key("user-1", "client-1");

    assert_ne!(base, ConsentStateCache::key("user-1", "client-2"));
    assert_ne!(base, ConsentStateCache::key("user-2", "client-1"));
    // 键前缀随值格式一同更换，新代码不会读到旧格式的无版本值
    assert!(base.starts_with("chenxing:oauth:consent-state:"));
    // user_id / client_id 不得出现在 keyspace 中
    assert!(!base.contains("user-1"));
    assert!(!base.contains("client-1"));
}

#[test]
fn cache_only_ttl_still_covers_refresh_token_absolute_lifetime() {
    // 仅缓存模式没有权威回源，键一到期撤销就失效，因此必须覆盖 refresh token
    // 的绝对寿命。生产模式有数据库回源，不受此约束（见常量文档）。
    assert_eq!(
        CONSENT_STATE_CACHE_ONLY_TTL_SECONDS,
        (REFRESH_TOKEN_ABSOLUTE_TTL_DAYS * 24 * 60 * 60) as u64
    );
    assert!(CONSENT_STATE_CACHE_TTL_SECONDS < CONSENT_STATE_CACHE_ONLY_TTL_SECONDS);
}
