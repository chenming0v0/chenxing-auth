//! 首个 Owner 引导端点的滥用防护（#279）。
//!
//! 引导端点是 AGENTS.md 里唯一允许匿名访问的管理接口：Owner 不存在时没有任何
//! 凭据可以要求，否则新部署永远无法完成初始化。这个既定例外不变，本模块处理的
//! 是它之前完全裸奔带来的两个可利用面。
//!
//! # 先到先得抢注
//!
//! 未初始化实例暴露在公网时，谁先 `POST /api/v1/admin/bootstrap` 谁就是 Owner，
//! 合法管理员随后只能拿到 `bootstrap_already_completed`。匿名这一点无法取消，
//! 但可以让批量尝试变得昂贵且留痕：
//!
//! - 按源 IP 的滑动窗口配额（[`BOOTSTRAP_ATTEMPT_LIMIT`] 次 /
//!   [`BOOTSTRAP_ATTEMPT_WINDOW_MS`]）。引导在一个部署的一生中只该成功一次，
//!   人类操作员即使输错几次也远低于该配额，而扫描器的成本被放大到分钟级。
//! - 每次被拒都写审计，运维能在事后看出「有人在抢」而不是只看到一次成功创建。
//!
//! 限流刻意早于 Argon2 口令哈希：慢哈希本身是 19 MiB 内存的计算成本，让匿名请求
//! 无限触发它等于送出一个内存放大的 DoS 面。
//!
//! # 初始化状态探测
//!
//! `GET /api/v1/admin/bootstrap/status` 原先向任何匿名调用者返回 `initialized`
//! 布尔，等于给扫描器提供了一个免费、可缓存、无审计的预言机：一次 GET 即可从
//! 大批地址里筛出「还没有 Owner、可以抢」的实例。
//!
//! 已初始化后该端点返回与未注册路由完全一致的 404（见
//! [`hidden_bootstrap_status`]），匿名调用者无法据此区分「这是一台已初始化的辰星
//! 实例」和「这个路径不存在」。未初始化时仍然如实返回 `initialized: false`——
//! 初始化页面必须能判断要不要显示，这是引导例外的一部分，不是疏漏。
//!
//! 探测面因此从「免费 GET」收敛到「受限流、留审计的 POST」。

use axum::response::Response;

use crate::{audit::AuditEvent, auth_limiter::MissingSourceIpPolicy, error, state::AppState};

/// 引导尝试的滑动窗口长度（毫秒）。
pub const BOOTSTRAP_ATTEMPT_WINDOW_MS: i64 = 60_000;
const _: () = assert!(BOOTSTRAP_ATTEMPT_WINDOW_MS >= 10_000);

/// 单个源 IP 在一个窗口内允许的引导尝试次数。
///
/// 取 5 而不是 1：口令强度校验、用户名冲突等合法失败都会消耗配额，操作员必须
/// 有重试余量。上界仍然足够低——扫描器要在被限流前只能试 5 次。
pub const BOOTSTRAP_ATTEMPT_LIMIT: u32 = 5;

/// 校验源 IP 的引导尝试配额。返回 `Some(response)` 表示必须直接拒绝。
///
/// 失败一律 fail closed：限流器不可用时放行等于「打掉 Redis 就能无限抢注」。
pub(crate) async fn enforce_bootstrap_attempt_limit(
    state: &AppState,
    source_ip: Option<&str>,
) -> Option<Response> {
    let Some(source_ip) = source_ip else {
        return match state.config.missing_source_ip_policy {
            MissingSourceIpPolicy::Skip => {
                tracing::warn!(
                    event = "bootstrap.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Skip.as_str(),
                    "owner bootstrap attempt is not rate limited without a trusted source IP"
                );
                None
            }
            MissingSourceIpPolicy::Reject => {
                tracing::error!(
                    event = "bootstrap.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "owner bootstrap attempt rejected without a trusted source IP"
                );
                Some(error::service_unavailable(
                    "bootstrap_source_unavailable",
                    "owner bootstrap requires a resolvable client address",
                ))
            }
        };
    };

    match state
        .qps
        .allow_scoped(
            &attempt_scope(source_ip),
            BOOTSTRAP_ATTEMPT_LIMIT,
            BOOTSTRAP_ATTEMPT_WINDOW_MS,
        )
        .await
    {
        Ok(true) => None,
        Ok(false) => {
            record_bootstrap_denial(state, Some(source_ip), "rate_limited").await;
            Some(error::too_many_requests(
                "bootstrap_rate_limited",
                "too many owner bootstrap attempts; retry later",
            ))
        }
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                event = "bootstrap.rate_limit_unavailable",
                "owner bootstrap rate limit check failed"
            );
            Some(error::service_unavailable(
                "bootstrap_unavailable",
                "owner bootstrap is temporarily unavailable",
            ))
        }
    }
}

/// 已初始化实例对引导状态查询的回答：与未注册路由逐字节一致的 404。
///
/// 必须和 `api::static_files` 的协议路径 404 完全相同（同 code、同 message），
/// 否则响应体差异会把预言机重新打开。
pub(crate) fn hidden_bootstrap_status() -> Response {
    error::not_found("not_found", "not found")
}

/// 引导尝试被拒的审计事件。
///
/// `actor_type` 用 `bootstrap` 与成功路径保持一致，便于按 actor 检索整条引导时间线。
/// 源 IP 由 [`AuditEvent::authentication_failure`] 规范化后写入 `source_ip`，
/// 该键在审计脱敏白名单内。
pub(crate) async fn record_bootstrap_denial(
    state: &AppState,
    source_ip: Option<&str>,
    reason: &str,
) {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
            "owner_bootstrap".to_owned(),
            "bootstrap".to_owned(),
            None,
            "user".to_owned(),
            None,
            reason,
            None,
            source_ip,
        ))
        .await;
}

/// 引导尝试配额的 Redis 作用域 key。
///
/// 对外可见是为了让集成测试能直接饱和窗口：走 HTTP 打满配额要付
/// [`BOOTSTRAP_ATTEMPT_LIMIT`] 次 Argon2（每次 19 MiB 内存），
/// 而测试要验证的是「限流是否被调用」，不是慢哈希本身。
pub fn attempt_scope(source_ip: &str) -> String {
    format!("chenxing:bootstrap:attempt:{source_ip}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn attempt_scope_is_namespaced_away_from_the_qps_keys() {
        let scope = attempt_scope("203.0.113.7");
        assert_eq!(scope, "chenxing:bootstrap:attempt:203.0.113.7");
        // 与 `chenxing:qps:source:*` 共用 key 会让引导尝试消耗 OAuth 的源配额。
        assert!(!scope.starts_with("chenxing:qps:"));
    }

    /// 已初始化后的状态响应必须与未注册路由的 404 完全一致，否则预言机仍然存在。
    #[tokio::test]
    async fn hidden_status_matches_the_generic_not_found_response() {
        let response = hidden_bootstrap_status();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("hidden status body");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(payload["code"], "not_found");
        assert_eq!(payload["message"], "not found");
    }

    /// 配额必须留出人类重试余量，同时远低于扫描器需要的尝试次数。
    #[test]
    fn attempt_budget_stays_within_the_intended_order_of_magnitude() {
        assert!((2..=10).contains(&BOOTSTRAP_ATTEMPT_LIMIT));
    }
}
