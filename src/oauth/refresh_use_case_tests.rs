//! 单元测试：刷新令牌用例的纯判定逻辑（scope 选择与墓碑分类）。
//!
//! 这两块都不碰 Redis：scope 选择是纯函数，墓碑分类只依赖墓碑内容和当前时刻。
//! 涉及真实 Redis 语义的并发轮换与 family 撤销由集成测试覆盖。

use super::{TombstoneDisposition, classify_tombstone, select_scopes};
use crate::oauth::refresh_store::{
    REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS, Tombstone, TombstoneState,
};
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

/// Issue #278：并发刷新中的落败请求可能在 CAS 处失败，也可能在 `find` 处就
/// 看不到 token——落到哪条路径只取决于与胜者的相对时序。分类必须只看墓碑，
/// 否则正常并发刷新会随机撤销整个 family。
#[test]
fn recent_consumption_is_a_concurrency_race_on_every_missing_path() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);

    for age in 0..=REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS {
        assert_eq!(
            classify_tombstone(
                &tombstone(TombstoneState::Consumed, now.unix_timestamp() - age),
                now
            ),
            TombstoneDisposition::ConcurrentRace,
            "a {age}s old consumption must not revoke the family"
        );
    }
}

/// 宽限窗口锚定在消费时刻，不随重复提交刷新：过窗后的提交仍是 replay，
/// 攻击者无法靠反复提交把 family 撤销无限推后。
#[test]
fn consumption_past_the_grace_window_is_a_replay() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);
    let stale = now.unix_timestamp() - REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS - 1;

    assert_eq!(
        classify_tombstone(&tombstone(TombstoneState::Consumed, stale), now),
        TombstoneDisposition::Replay
    );
}

/// 升级前写入的墓碑没有 `recorded_at`（默认 0），必须仍然按 replay 处理。
#[test]
fn legacy_consumption_tombstone_is_a_replay() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);

    assert_eq!(
        classify_tombstone(&tombstone(TombstoneState::Consumed, 0), now),
        TombstoneDisposition::Replay
    );
}

#[test]
fn non_consumption_tombstones_never_trigger_replay_revocation() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);

    assert_eq!(
        classify_tombstone(
            &tombstone(TombstoneState::ExplicitRevoke, now.unix_timestamp()),
            now,
        ),
        TombstoneDisposition::ExplicitRevoke
    );
    assert_eq!(
        classify_tombstone(
            &tombstone(TombstoneState::FamilyRevoked, now.unix_timestamp()),
            now,
        ),
        TombstoneDisposition::FamilyRevoked
    );
}
