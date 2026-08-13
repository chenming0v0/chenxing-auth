use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::{api::extract::SessionRead, error, state::AppState};

/// 用户端只读的「套餐与权益」页接口。`entitlements` 是有序数组，
/// 前端按顺序渲染卡片；后端新增权益项只需向数组追加元素。
///
/// 序列化约定：
/// - `plan: null` + `entitlements: []` → 没有生效套餐（平台未开放自助接入）。
///   这是一种状态而不是错误，因此仍返回 200；
/// - `limit` 为数字 → 有上限；
/// - `limit: null` → 无限（前端显示 ∞，例如每月授权）；
/// - 没有 `limit` 字段 → 只是个数值、无上限概念（例如 QPS）。
#[derive(Debug, Serialize)]
struct EntitlementsResponse {
    plan: Option<PlanSummary>,
    entitlements: Vec<EntitlementItem>,
}

#[derive(Debug, Serialize)]
struct PlanSummary {
    code: String,
    name: String,
    description: Option<String>,
    validity: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum EntitlementItem {
    Limited(LimitedEntitlement),
    Unlimited(UnlimitedEntitlement),
    Numeric(NumericEntitlement),
}

#[derive(Debug, Serialize)]
struct LimitedEntitlement {
    key: &'static str,
    label: &'static str,
    used: u64,
    limit: u64,
}

#[derive(Debug, Serialize)]
struct UnlimitedEntitlement {
    key: &'static str,
    label: &'static str,
    used: u64,
    limit: Option<u64>,
}

#[derive(Debug, Serialize)]
struct NumericEntitlement {
    key: &'static str,
    label: &'static str,
    used: u64,
}

pub async fn current_entitlements(State(state): State<AppState>, session: SessionRead) -> Response {
    let effective = match state.plans.effective_plan_for_user(session.user_id).await {
        Ok(Some(effective)) => effective,
        // 本端点的职责是描述当前状态，「没有生效套餐」就是一种状态。
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(EntitlementsResponse {
                    plan: None,
                    entitlements: Vec::new(),
                }),
            )
                .into_response();
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load plan for user entitlements");
            return error::internal();
        }
    };
    let plan = effective.plan;
    let quota_limits = plan.auth_quota_limits();

    // 配额统计要遍历该用户全部 Client：分页拉全（单用户规模受套餐配额上界约束），
    // 修复前 `list_for_user` 的 200 条硬上限会静默漏算超出的 Client（Issue #415）。
    let clients = match state.clients.list_all_for_user(session.user_id).await {
        Ok(clients) => clients,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list OAuth clients for entitlements");
            return error::internal();
        }
    };

    // Redis 计数按 client_id 保存，用户维度需要遍历其所有 Client 求和。
    let mut daily_used = 0_u64;
    let mut monthly_used = 0_u64;
    for client in &clients {
        match state
            .oauth_quotas
            .snapshot_at(&client.client_id, Some(quota_limits), state.clock.now())
            .await
        {
            Ok(snapshot) => {
                daily_used = daily_used.saturating_add(snapshot.daily_used);
                monthly_used = monthly_used.saturating_add(snapshot.monthly_used);
            }
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to read OAuth quota snapshot");
                return error::internal();
            }
        }
    }

    let mut entitlements = Vec::with_capacity(4);
    entitlements.push(EntitlementItem::Limited(LimitedEntitlement {
        key: "oauth_clients",
        label: "OAuth 应用数",
        used: clients.len() as u64,
        limit: plan.oauth_clients_limit.max(0) as u64,
    }));
    entitlements.push(EntitlementItem::Limited(LimitedEntitlement {
        key: "daily_auth",
        label: "每日授权调用",
        used: daily_used,
        limit: quota_limits.daily_auth_limit,
    }));
    match quota_limits.monthly_auth_limit {
        Some(limit) => entitlements.push(EntitlementItem::Limited(LimitedEntitlement {
            key: "monthly_auth",
            label: "每月授权调用",
            used: monthly_used,
            limit,
        })),
        None => entitlements.push(EntitlementItem::Unlimited(UnlimitedEntitlement {
            key: "monthly_auth",
            label: "每月授权调用",
            used: monthly_used,
            limit: None,
        })),
    }
    // QPS 只是套餐展示值，无「用量/上限」概念，因此不带 limit 字段；
    // 套餐不限并发（max_qps 为 NULL）时不返回该卡片。
    if let Some(max_qps) = plan.max_qps {
        entitlements.push(EntitlementItem::Numeric(NumericEntitlement {
            key: "max_qps",
            label: "最大并发（请求/秒）",
            used: max_qps.max(0) as u64,
        }));
    }

    (
        StatusCode::OK,
        Json(EntitlementsResponse {
            plan: Some(PlanSummary {
                code: plan.code,
                name: plan.name,
                description: plan.description,
                validity: validity_string(effective.expires_at),
            }),
            entitlements,
        }),
    )
        .into_response()
}

/// `expires_at = None` 表示永久有效；否则输出 RFC3339 时间字符串。
fn validity_string(expires_at: Option<OffsetDateTime>) -> String {
    match expires_at {
        Some(expires_at) => expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| expires_at.to_string()),
        None => "permanent".to_owned(),
    }
}
