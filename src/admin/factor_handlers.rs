//! 管理端认证因子恢复接口（#258）。
//!
//! `AUTH_ENCRYPTION_KEYS` 里的旧 key 一旦退役，仍以它加密的 TOTP 种子永久不可读，
//! 而懒迁移依赖一次成功验证，验证本身已经失败——这条路上没有任何自助恢复出口。
//! 本模块补上三个动作：
//!
//! - `GET /api/v1/admin/auth-factors/key-health`：退役旧 key 之前先看还有多少密文
//!   引用环外或非 active 的 kid。
//! - `GET /api/v1/admin/users/{user_id}/auth-factors`：单账号因子状态，回答
//!   「这个人是被密钥退役锁死了，还是自己输错了码」。
//! - `DELETE /api/v1/admin/users/{user_id}/auth-factors/totp`：丢弃不可读的密文，
//!   让账号回到「无因子」状态并在下次登录重新注册。
//! - Passkey 重置见 [`super::passkey_recovery`]（#460）：末位 Owner 丢失全部
//!   Passkey 时走系统 Token，不能依赖现有 Session。
//!
//! 这些端点都不返回 kid、密文、种子或 Passkey 凭据材料：管理员做决策只需要
//! 状态名，拿到材料只会泄漏到 API 与前端日志里。

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminRead, AdminWrite},
    audit::AuditEvent,
    auth_factors::service::TotpResetOutcome,
    error,
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug, Serialize)]
pub struct TotpFactorStatusResponse {
    /// `current` / `rotatable` / `legacy` / `unavailable`。
    /// `unavailable` 表示密文引用的 kid 已不在密钥环内，账号已被锁死。
    key_state: &'static str,
    /// 密文是否仍可被当前密钥环解密。
    readable: bool,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct AccountFactorStatusResponse {
    user_id: UserId,
    methods: Vec<String>,
    totp: Option<TotpFactorStatusResponse>,
}

#[derive(Debug, Serialize)]
pub struct EncryptionKeyHealthResponse {
    total: i64,
    scanned: i64,
    current: i64,
    rotatable: i64,
    legacy: i64,
    unavailable: i64,
    truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct TotpResetResponse {
    user_id: UserId,
    /// 删除前密文的可读状态，供调用方确认这次重置救的是不是一个被锁死的账号。
    previous_key_state: &'static str,
    /// 重置同时撤销了该账号的全部会话与已签发 Refresh Token（`session_epoch`
    /// 被推进，两者在同一水位上一起失效，Issue #409），固定为 true。
    credentials_revoked: bool,
}

pub async fn user_auth_factors(
    State(state): State<AppState>,
    admin: AdminRead,
    Path(user_id): Path<UserId>,
) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ManageUsers).await {
        return response;
    }
    match state.factors.account_factor_status(user_id).await {
        Ok(Some(status)) => (
            StatusCode::OK,
            Json(AccountFactorStatusResponse {
                user_id,
                methods: status.methods,
                totp: status.totp.map(|totp| TotpFactorStatusResponse {
                    key_state: totp.key_state.as_str(),
                    readable: totp.key_state.is_readable(),
                    updated_at: totp.updated_at,
                }),
            }),
        )
            .into_response(),
        Ok(None) => error::not_found("user_not_found", "user was not found"),
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load account factor status");
            error::internal()
        }
    }
}

pub async fn auth_factor_key_health(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::RotateKeys).await {
        return response;
    }
    match state.factors.encryption_key_health().await {
        Ok(health) => (
            StatusCode::OK,
            Json(EncryptionKeyHealthResponse {
                total: health.total,
                scanned: health.scanned,
                current: health.current,
                rotatable: health.rotatable,
                legacy: health.legacy,
                unavailable: health.unavailable,
                truncated: health.truncated,
            }),
        )
            .into_response(),
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to inspect factor encryption key health");
            error::internal()
        }
    }
}

/// 重置某个账号的 TOTP 因子。
///
/// 权限是 Owner 专属的 `ManageAuthFactors`，而不是 `ManageUsers`：这个动作把账号
/// 降级为「只有密码」，下次密码登录可签发普通 Session，并从安全设置注册新的
/// TOTP。它是账号接管链条上的一环，必须与普通用户管理分权。
///
/// 撤销会话与删除因子由 `AuthFactorService::reset_totp_factor` 在同一事务内原子
/// 完成（Issue #331）：`Missing`/`UnknownUser` 时整体回滚，不会留下「会话已撤、
/// 因子未删」的中间态。`revoke_all_for_user_in_transaction` 推进该用户的
/// `session_epoch`：Cookie 会话与全部已签发 Refresh Token 在同一水位上一起
/// 失效（Issue #409），不会留下「TOTP 已重置、旧 Refresh Token 仍能换取
/// access token」的恢复通道后门。
pub async fn reset_user_totp_factor(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(user_id): Path<UserId>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageAuthFactors)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let outcome = match state.factors.reset_totp_factor(user_id).await {
        Ok(outcome) => outcome,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to reset TOTP factor");
            return error::internal();
        }
    };
    let key_state = match outcome {
        TotpResetOutcome::Removed { key_state } => key_state,
        // 两种竞态（并发重置抢先、账号被并发删除）在事务内整体回滚，会话保持
        // 原样；如实回 404，不要伪装成服务端故障。
        TotpResetOutcome::Missing => {
            return error::not_found("totp_factor_not_found", "TOTP factor was not found");
        }
        TotpResetOutcome::UnknownUser => {
            return error::not_found("user_not_found", "user was not found");
        }
    };
    let (actor_type, actor_id) = actor.audit_fields();
    // 因子已经删除，这个既成事实不因审计写入失败而改写；best_effort 的失败日志
    // 保留人工补录所需的上下文。元数据只含状态名，不含 kid 与种子。
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            crate::audit::AuditAction::UserTotpFactorReset,
            "authentication_factor".to_owned(),
            Some(user_id.to_string()),
            serde_json::json!({
                "result": "success",
                "method": "totp",
                "previous_key_state": key_state.as_str(),
                "credentials_revoked": true,
            }),
        ))
        .await;
    (
        StatusCode::OK,
        Json(TotpResetResponse {
            user_id,
            previous_key_state: key_state.as_str(),
            credentials_revoked: true,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{AccountFactorStatusResponse, EncryptionKeyHealthResponse, TotpResetResponse};
    use crate::auth_factors::crypto::SecretKeyState;

    #[test]
    fn factor_status_response_reports_state_without_key_material() {
        let value = serde_json::to_value(AccountFactorStatusResponse {
            user_id: 7,
            methods: vec!["totp".to_owned()],
            totp: Some(super::TotpFactorStatusResponse {
                key_state: SecretKeyState::Unavailable.as_str(),
                readable: false,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            }),
        })
        .expect("factor status serializes");

        assert_eq!(value["totp"]["key_state"], "unavailable");
        assert_eq!(value["totp"]["readable"], false);
        assert_eq!(value["totp"]["updated_at"], "1970-01-01T00:00:00Z");
        // kid、密文和种子都不属于管理响应。
        assert!(value["totp"].get("kid").is_none());
        assert!(value["totp"].get("encrypted_secret").is_none());
        assert!(value["totp"].get("secret").is_none());
    }

    #[test]
    fn reset_response_reports_previous_state_and_credential_revocation() {
        let value = serde_json::to_value(TotpResetResponse {
            user_id: 7,
            previous_key_state: SecretKeyState::Unavailable.as_str(),
            credentials_revoked: true,
        })
        .expect("reset response serializes");

        assert_eq!(value["previous_key_state"], "unavailable");
        assert_eq!(value["credentials_revoked"], true);
    }

    #[test]
    fn key_health_response_exposes_counts_only() {
        let value = serde_json::to_value(EncryptionKeyHealthResponse {
            total: 3,
            scanned: 3,
            current: 1,
            rotatable: 1,
            legacy: 0,
            unavailable: 1,
            truncated: false,
        })
        .expect("key health serializes");

        assert_eq!(value["unavailable"], 1);
        assert_eq!(value["truncated"], false);
        assert!(value.get("active_kid").is_none());
        assert!(value.get("kids").is_none());
    }
}
