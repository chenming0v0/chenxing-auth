//! 手机号一键登录兑换端点（Issue #709）。
//!
//! `POST /api/v1/auth/chenxing/exchange` 接收浏览器持有的辰星 Access Token，
//! 校验它确实是本 Issuer 为允许的 OAuth Client 签发、且授权（grant gate）此刻
//! 仍然覆盖 `cltermux:access`，再为「已绑定的 CLtermux 账号」签发一枚 300 秒
//! 的 RS256 会话令牌。
//!
//! 与后台 resolve 端点的差异：resolve 是 CLtermux 服务端到服务端的入站调用，
//! 额外校验 `CLTERMUX_INTEROP_INBOUND_TOKEN`；本端点由用户浏览器直接调用，
//! 没有入站 interop 凭据，认证材料只有用户自己的 Access Token。
//!
//! 校验顺序与 `handlers.rs::resolve` 对齐（成本递增、尽早拒绝），并在签发前做
//! 一次按 subject 的滑动窗口限流。`device_id` / `device_info` 只进审计，不作为
//! 设备判定依据，也永远不落库。

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

use crate::{
    api::extract::{ApiJson, RequestIssuer},
    audit::AuditEvent,
    error,
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        response::with_no_store_headers,
        token::{TokenError, decode_userinfo_token, issue_session_token_at},
    },
    state::AppState,
    users::domain::{UserId, UserStatus},
};

use super::{LinkedAccountServiceError, response};

const REQUIRED_SCOPE: &str = "cltermux:access";
const SESSION_TOKEN_LIFETIME_SECONDS: u64 = 300;
const MAX_DEVICE_ID_BYTES: usize = 255;
const MAX_DEVICE_INFO_BYTES: usize = 1024;

/// 按 subject 的兑换限流：10 次 / 60 秒。
///
/// 正常一键登录在一分钟内远低于 10 次；该上限只用来阻挡单个账号被脚本化地
/// 反复兑换会话令牌。窗口与阈值是端点语义，不引入新的可配置项，避免部署面
/// 继续膨胀。
const EXCHANGE_RATE_LIMIT: u32 = 10;
const EXCHANGE_RATE_WINDOW_MS: i64 = 60_000;

const BAD_REQUEST_MESSAGE: &str = "the exchange request is invalid";
const INVALID_TOKEN_MESSAGE: &str = "the Chenxing access token is invalid";
const UNAVAILABLE_MESSAGE: &str = "authorization state is unavailable";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeInput {
    /// 审计用设备标识；必填、非空、≤255 字节，不做设备判定。
    pub device_id: String,
    /// 审计用设备描述；可选、≤1024 字节，明文永不落库。
    #[serde(default)]
    pub device_info: Option<String>,
}

impl fmt::Debug for ExchangeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeInput")
            .field("device_id", &self.device_id)
            .field(
                "device_info",
                &self.device_info.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Serialize)]
struct ExchangeResponse {
    session_token: String,
    uid: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

pub async fn exchange(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ExchangeInput>,
) -> Response {
    if input.device_id.is_empty() || input.device_id.len() > MAX_DEVICE_ID_BYTES {
        return error::bad_request("invalid_request", BAD_REQUEST_MESSAGE);
    }
    if input
        .device_info
        .as_deref()
        .is_some_and(|value| value.len() > MAX_DEVICE_INFO_BYTES)
    {
        return error::bad_request("invalid_request", BAD_REQUEST_MESSAGE);
    }

    let Some(config) = state.config.cltermux.as_ref() else {
        return denied(&state, None).await;
    };
    let Some(token) = bearer_token(&headers) else {
        return denied(&state, None).await;
    };
    let claims = match decode_userinfo_token(&state.keys, issuer.issuer().as_str(), token) {
        Ok(claims) => claims,
        Err(_) => return denied(&state, None).await,
    };
    // 撤销检查沿用 resolve 的口径：Redis 故障同样 fail-closed，因为无法证明
    // 令牌未被撤销时不能签出新的会话令牌。
    match state.revocations.is_revoked(token).await {
        Ok(false) => {}
        Ok(true) | Err(_) => return denied(&state, Some(&claims.sub)).await,
    }
    if !config.allowed_client_ids.iter().any(|id| id == &claims.aud) {
        return denied(&state, Some(&claims.sub)).await;
    }

    let presented = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let scopes = match effective_grant_scopes(&state, &claims.sub, &claims.aud, &presented).await {
        Ok(grant) => grant.scopes,
        Err(GrantGateError::Denied(_)) => return denied(&state, Some(&claims.sub)).await,
        Err(GrantGateError::Unavailable(_)) => {
            return unavailable(&state, Some(&claims.sub)).await;
        }
    };
    if !scopes.iter().any(|scope| scope == REQUIRED_SCOPE) {
        record_denied(&state, Some(&claims.sub), "insufficient_scope").await;
        return error::forbidden(
            "insufficient_scope",
            "the access token lacks the required scope",
        );
    }

    let Ok(user_id) = claims.sub.parse::<UserId>() else {
        return denied(&state, Some(&claims.sub)).await;
    };
    match state.users.find_profile(user_id).await {
        Ok(Some(profile)) if UserStatus::parse(&profile.status) == Some(UserStatus::Active) => {}
        Ok(Some(_)) | Ok(None) => return denied(&state, Some(&claims.sub)).await,
        Err(_) => return unavailable(&state, Some(&claims.sub)).await,
    }

    // 限流放在签发之前：它保护的是「会话令牌签发」这个动作本身，必须在任何
    // 令牌被签出之前生效。
    match state
        .qps
        .allow_scoped(
            &format!("chenxing:cltermux-exchange:{}", claims.sub),
            EXCHANGE_RATE_LIMIT,
            EXCHANGE_RATE_WINDOW_MS,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            record_denied(&state, Some(&claims.sub), "rate_limited").await;
            return error::too_many_requests(
                "rate_limited",
                "the exchange request is rate limited",
            );
        }
        Err(_) => return unavailable(&state, Some(&claims.sub)).await,
    }

    let binding = match state.linked_accounts.resolve(user_id).await {
        Ok(binding) => binding,
        Err(LinkedAccountServiceError::NotFound) => {
            record_denied(&state, Some(&claims.sub), "account_not_linked").await;
            return error::forbidden("account_not_linked", "the user has no linked account");
        }
        Err(error_value) => {
            record_denied(
                &state,
                Some(&claims.sub),
                response::service_code(&error_value),
            )
            .await;
            return response::map_service_error(error_value);
        }
    };
    match binding.account_status.as_str() {
        "disabled" => {
            record_denied(&state, Some(&claims.sub), "account_disabled").await;
            return error::forbidden("account_disabled", "the linked account is disabled");
        }
        "missing" => {
            record_denied(&state, Some(&claims.sub), "account_not_linked").await;
            return error::forbidden("account_not_linked", "the user has no linked account");
        }
        _ => {}
    }

    let now = state.clock.now();
    let session_token = match issue_session_token_at(
        &state.keys,
        issuer.issuer().as_str(),
        &claims.sub,
        &claims.aud,
        &scopes,
        SESSION_TOKEN_LIFETIME_SECONDS,
        now,
        &binding.uid,
        &binding.binding_id,
        binding.binding_version,
    ) {
        Ok(token) => token,
        Err(token_error) => {
            // 只记录安全的原因分类，绝不输出签名错误细节或令牌材料。
            match &token_error {
                TokenError::SigningUnavailable => {
                    tracing::error!("CLtermux session token signing is unavailable");
                }
                _ => tracing::error!("failed to sign CLtermux session token"),
            }
            return unavailable(&state, Some(&claims.sub)).await;
        }
    };
    let expires_at = now + time::Duration::seconds(SESSION_TOKEN_LIFETIME_SECONDS as i64);
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            Some(claims.sub.clone()),
            crate::audit::AuditAction::CltermuxExchange,
            "linked_account".to_owned(),
            Some(binding.binding_id.clone()),
            serde_json::json!({
                "provider": "cltermux",
                "uid": &binding.uid,
                "device_id": &input.device_id,
                "result": "success",
            }),
        ))
        .await;

    with_no_store_headers(
        (
            StatusCode::OK,
            Json(ExchangeResponse {
                session_token,
                uid: binding.uid,
                expires_at,
            }),
        )
            .into_response(),
    )
}

/// 统一的 Chenxing 令牌无效回应：先留痕再返回 401。
async fn denied(state: &AppState, actor_id: Option<&str>) -> Response {
    record_denied(state, actor_id, "invalid_chenxing_token").await;
    error::unauthorized("invalid_chenxing_token", INVALID_TOKEN_MESSAGE)
}

/// 统一的存储/限流基础设施不可用回应：先留痕再返回 503。
async fn unavailable(state: &AppState, actor_id: Option<&str>) -> Response {
    record_denied(state, actor_id, "provider_unavailable").await;
    error::service_unavailable("provider_unavailable", UNAVAILABLE_MESSAGE)
}

/// 记录一次兑换拒绝/失败。失败只记录稳定的 `code`；`device_id` 与
/// `device_info` 不进入失败事件的元数据，任何令牌材料都不记录。
async fn record_denied(state: &AppState, actor_id: Option<&str>, code: &str) {
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            actor_id.map(str::to_owned),
            crate::audit::AuditAction::CltermuxExchangeDenied,
            "linked_account".to_owned(),
            None,
            serde_json::json!({"code": code}),
        ))
        .await;
}

/// 从 `Authorization` 头提取 Bearer 令牌。与 `handlers.rs::resolve` 的私有
/// 助手同源：本端点不使用入站 interop 凭据，因此不能复用那条校验链。
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token)
        .filter(|token| !token.is_empty())
}
