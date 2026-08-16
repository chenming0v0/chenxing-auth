//! Persist 之后的签发围栏（Issue #475 / #476）。
//!
//! 授权码兑换的闸门在 Client 行锁和 Redis CAS 之前。撤销同意在闸门通过之后、
//! Refresh Token 落盘之前提交时，闸门看到的是旧版本，撤销也看不到尚未存在的
//! family。这里在 persist 之后再读一次 PostgreSQL 权威行：版本变了、已撤销或
//! 行没了，就不得返回令牌。
//!
//! Redis 同意缓存只能拒绝、不能放行，300 秒 TTL 也太粗，围栏必须回源数据库。

use crate::{consents::domain::ConsentState, state::AppState, users::domain::UserId};

/// 闸门放行时拍下的签发快照。`#475` 填 `consent_version`；`session_epoch`
/// 留给 `#476`，本文件不实现代际复核。
pub struct IssuanceSnapshot {
    pub consent_version: Option<i64>,
    pub session_epoch: Option<i64>,
}

/// 围栏拒绝与存储故障必须可区分：前者销毁刚写下的 Refresh Token 并回
/// `invalid_grant`，后者不能把一次数据库抖动当成用户撤销。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceFenceError {
    Denied(&'static str),
    Unavailable(&'static str),
}

impl IssuanceFenceError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Denied(reason) | Self::Unavailable(reason) => reason,
        }
    }
}

/// 对照闸门快照复核当前权威状态。`consent_version` 为空时跳过同意复核，
/// 供后续只填 session 代际的调用方使用。
pub async fn confirm_issuance_snapshot(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    expected: &IssuanceSnapshot,
) -> Result<(), IssuanceFenceError> {
    if let Some(expected_version) = expected.consent_version {
        confirm_consent_version(state, user_id, client_id, expected_version).await?;
    }
    let _ = expected.session_epoch;
    Ok(())
}

async fn confirm_consent_version(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    expected_version: i64,
) -> Result<(), IssuanceFenceError> {
    let Ok(subject) = user_id.parse::<UserId>() else {
        return Err(IssuanceFenceError::Denied("invalid_subject"));
    };
    match state.consents.consent_state(subject, client_id).await {
        Ok(current) => consent_matches(expected_version, current),
        Err(database_error) => {
            tracing::error!(
                error = %database_error,
                "failed to reconfirm OAuth consent version after token persist"
            );
            Err(IssuanceFenceError::Unavailable(
                "consent_version_check_failed",
            ))
        }
    }
}

fn consent_matches(
    expected_version: i64,
    current: Option<ConsentState>,
) -> Result<(), IssuanceFenceError> {
    match current {
        Some(state) if state.revoked => Err(IssuanceFenceError::Denied("consent_revoked")),
        Some(state) if state.version == expected_version => Ok(()),
        Some(_) => Err(IssuanceFenceError::Denied("consent_version_changed")),
        None => Err(IssuanceFenceError::Denied("consent_missing")),
    }
}

#[cfg(test)]
mod tests {
    use super::{IssuanceFenceError, consent_matches};
    use crate::consents::domain::ConsentState;

    #[test]
    fn matching_active_version_passes() {
        assert_eq!(
            consent_matches(3, Some(ConsentState::new(false, 3))),
            Ok(())
        );
    }

    #[test]
    fn revoked_row_is_denied_even_when_version_matches() {
        assert_eq!(
            consent_matches(3, Some(ConsentState::new(true, 3))),
            Err(IssuanceFenceError::Denied("consent_revoked"))
        );
    }

    #[test]
    fn version_change_is_denied() {
        assert_eq!(
            consent_matches(3, Some(ConsentState::new(false, 4))),
            Err(IssuanceFenceError::Denied("consent_version_changed"))
        );
    }

    #[test]
    fn missing_row_is_denied() {
        assert_eq!(
            consent_matches(3, None),
            Err(IssuanceFenceError::Denied("consent_missing"))
        );
    }
}
