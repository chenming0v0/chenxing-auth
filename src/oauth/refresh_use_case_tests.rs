//! 单元测试：刷新令牌用例的纯判定逻辑（scope 选择与墓碑分类）。
//!
//! 这两块都不碰 Redis：scope 选择是纯函数，墓碑分类只依赖墓碑内容和当前时刻。
//! 涉及真实 Redis 语义的并发轮换与 family 撤销由集成测试覆盖。

use super::{TombstoneDisposition, classify_tombstone, select_scopes};
use crate::oauth::refresh_store::{Tombstone, TombstoneState};
use crate::oauth::{refresh::RefreshToken, token_use_case::OAuthError};
use time::{Duration, OffsetDateTime};

fn refresh_token() -> RefreshToken {
    RefreshToken::new_at(
        "cx_client".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned(), "profile".to_owned()],
        OffsetDateTime::UNIX_EPOCH + Duration::days(1),
    )
}

#[test]
fn omitted_scope_reuses_the_original_grant() {
    let refresh = refresh_token();

    assert_eq!(
        select_scopes(None, &refresh.scopes).expect("original scopes are valid"),
        refresh.scopes
    );
}

/// Issue #282：`scope=` 与 `scope=%20` 在表单解码后与省略参数无法区分，
/// 必须沿用原授权，而不是把 token 降级成零权限（并让轮换后永久丢失 scope）。
#[test]
fn blank_scope_reuses_the_original_grant_instead_of_dropping_it() {
    let refresh = refresh_token();

    for blank in ["", " ", "   ", "\t", "\n", " \t\n "] {
        assert_eq!(
            select_scopes(Some(blank), &refresh.scopes)
                .unwrap_or_else(|_| panic!("blank scope {blank:?} must reuse the grant")),
            refresh.scopes,
            "blank scope {blank:?} must not clear the grant"
        );
    }
}

#[test]
fn requested_scope_cannot_exceed_the_original_grant() {
    let refresh = refresh_token();

    let error = select_scopes(Some("openid email"), &refresh.scopes)
        .expect_err("scope escalation must be rejected");

    assert_eq!(
        error,
        OAuthError::BadRequest {
            code: "invalid_scope",
            description: "requested scope exceeds original grant",
        }
    );
}

/// 缩小 scope 仍然要求显式列出保留值——空 scope 不再是缩小的表达方式。
#[test]
fn explicitly_narrowed_scope_is_still_honoured() {
    let refresh = refresh_token();

    assert_eq!(
        select_scopes(Some("openid"), &refresh.scopes).expect("narrowing stays within the grant"),
        vec!["openid".to_owned()]
    );
}

#[test]
fn requested_scope_preserves_endpoint_order() {
    let refresh = refresh_token();

    assert_eq!(
        select_scopes(Some("profile openid"), &refresh.scopes)
            .expect("requested scopes are within the grant"),
        vec!["profile".to_owned(), "openid".to_owned()]
    );
}

fn tombstone(state: TombstoneState, recorded_at: i64) -> Tombstone {
    Tombstone {
        family_id: "family".to_owned(),
        client_id: "cx_client".to_owned(),
        user_id: "7".to_owned(),
        state,
        recorded_at,
    }
}

/// Issue #293：已消费凭据被再次提交就是重放，没有时间窗口豁免。
///
/// 曾经存在的 5 秒宽限窗口把窗口内的重复提交当成正常并发刷新放过，等于给
/// 刚窃取到凭据的攻击者一次「不触发 family 撤销」的免费尝试。消费时刻不再
/// 参与判定，因此无论墓碑多新都是重放。
#[test]
fn any_consumed_tombstone_is_a_replay_regardless_of_age() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);

    for recorded_at in [now.unix_timestamp(), now.unix_timestamp() - 3_600, 0] {
        assert_eq!(
            classify_tombstone(
                &tombstone(TombstoneState::Consumed, recorded_at),
                "cx_client"
            ),
            TombstoneDisposition::Replay,
            "a consumption recorded at {recorded_at} must revoke the family"
        );
    }
}

/// 主动撤销和 family 撤销都不是新的泄露信号：凭据已经死了，只拒绝当次请求。
#[test]
fn dead_credentials_do_not_trigger_another_revocation() {
    for state in [
        TombstoneState::ExplicitRevoke,
        TombstoneState::FamilyRevoked,
    ] {
        assert_eq!(
            classify_tombstone(&tombstone(state, 0), "cx_client"),
            TombstoneDisposition::AlreadyDead,
            "{state:?} must not be treated as a replay"
        );
    }
}

/// Issue #110：墓碑归属校验先于状态判定，否则任何 Client 都能提交别人的
/// 旧 token 来摧毁对方的 grant。
#[test]
fn a_foreign_client_can_never_revoke_someone_elses_family() {
    for state in [
        TombstoneState::Consumed,
        TombstoneState::ExplicitRevoke,
        TombstoneState::FamilyRevoked,
    ] {
        assert_eq!(
            classify_tombstone(&tombstone(state, 0), "cx_other_client"),
            TombstoneDisposition::ForeignClient,
            "{state:?} submitted by a foreign client must not revoke anything"
        );
    }
}
