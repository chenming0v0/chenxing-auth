//! `refresh_store` 的纯函数单测。
//!
//! 拆成独立文件而不是内联 `mod tests`：这里的判定注释密度较高，内联后
//! `refresh_store.rs` 会越过 500 行的源文件门槛。

use super::{FamilyScope, Tombstone, TombstoneState};

/// 升级前写入的墓碑没有 `state` / `recorded_at`：必须默认为 `Consumed`。
///
/// 默认值决定了旧墓碑的处置：`Consumed` 意味着再次提交就是重放并撤销 family，
/// 这是保守的一侧。若默认成 `ExplicitRevoke`，旧墓碑对应的泄露凭据被重放时
/// 就只会被静默拒绝，family 里的其它成员继续存活。
#[test]
fn legacy_tombstones_default_to_a_consumed_credential() {
    let tombstone: Tombstone =
        serde_json::from_str(r#"{"family_id":"family","client_id":"client","user_id":"user"}"#)
            .expect("legacy tombstone should deserialize");

    assert_eq!(tombstone.state, TombstoneState::Consumed);
    assert_eq!(tombstone.recorded_at, 0);
}

/// 旧格式 token 没有 `family_id`。它们不能共用同一个空后缀撤销键，否则撤销
/// 任意一个旧 token 都会给全部旧 token 写上同一个墓志，把它们连坐撤销。
#[test]
fn legacy_tokens_get_a_private_revocation_scope() {
    let first = FamilyScope::new("", "hash-one");
    let second = FamilyScope::new("", "hash-two");

    assert_ne!(first.revoked_key, second.revoked_key);
    assert_ne!(first.index_key, second.index_key);
    assert!(first.revoked_key.ends_with("legacy-token:hash-one"));
}

/// 有 family_id 时撤销单元与提交的是哪个成员无关：同一 family 的任意成员
/// 必须解析到同一组键，否则 family 撤销就不是幂等的。
#[test]
fn family_scope_ignores_which_member_was_submitted() {
    let from_first_member = FamilyScope::new("family-7", "hash-one");
    let from_second_member = FamilyScope::new("family-7", "hash-two");

    assert_eq!(
        from_first_member.revoked_key,
        from_second_member.revoked_key
    );
    assert_eq!(from_first_member.index_key, from_second_member.index_key);
}
