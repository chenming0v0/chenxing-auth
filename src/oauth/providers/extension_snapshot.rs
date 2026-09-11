//! 外部身份扩展条目的 serde 类型与契约约束。
//!
//! 扩展是「身份上挂的附加信息」：持久化条目来自数据库 JSONB，运行时条目由
//! 服务层组装（如订阅状态）。两层共用同一组约束，保证任何来源的条目都满足
//! 前端 guard（`web/src/api-response-guards.ts`）的校验上限。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::serde::rfc3339;

/// namespace 的最大长度，与前端 guard 的 128 上限一致。
pub const MAX_EXTENSION_NAMESPACE_LENGTH: usize = 128;
/// 单个条目的 fields 数量上限，与前端 guard 的 100 上限一致。
pub const MAX_EXTENSION_FIELDS: usize = 100;
/// 订阅扩展的固定 namespace。
pub const SUBSCRIPTION_EXTENSION_NAMESPACE: &str = "chenxing.subscription";
/// `remaining_days` 的哨兵值：NULL 的 `plan_expires_at` 表示永久有效，
/// 没有自然的天数表达，用 -1 显式标记而不是让前端猜。
pub const REMAINING_DAYS_PERMANENT: i64 = -1;

/// version 允许字符串或非负整数，与前端 guard 的判定保持一致。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExtensionVersion {
    Text(String),
    Number(u64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionField {
    pub key: String,
    pub label: String,
    /// 前端契约里的展示类型（text/number/boolean/status/datetime/duration_days/url）。
    /// 保持 String 而不是枚举：未知类型由前端渲染「不支持」标记，这里不拦截。
    pub field_type: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalIdentityExtension {
    pub namespace: String,
    pub version: ExtensionVersion,
    #[serde(with = "rfc3339")]
    pub fetched_at: OffsetDateTime,
    pub fields: Vec<ExtensionField>,
}

impl ExternalIdentityExtension {
    /// 构造即校验契约上限。超限条目直接丢弃（返回 None）而不是截断：
    /// 一个被截断的扩展比没有扩展更误导。
    pub fn try_new(
        namespace: String,
        version: ExtensionVersion,
        fetched_at: OffsetDateTime,
        fields: Vec<ExtensionField>,
    ) -> Option<Self> {
        if namespace.is_empty()
            || namespace.chars().count() > MAX_EXTENSION_NAMESPACE_LENGTH
            || fields.len() > MAX_EXTENSION_FIELDS
        {
            return None;
        }
        Some(Self {
            namespace,
            version,
            fetched_at,
            fields,
        })
    }
}

/// 订阅扩展：身份有生效套餐时，把 uid 与剩余天数作为运行时条目追加。
/// `plan_expires_at` 为 NULL 表示永久有效，用 -1 哨兵显式标记。
fn subscription_extension(
    identity: &super::repository::LinkedExternalIdentity,
) -> Option<ExternalIdentityExtension> {
    let hint = identity.subject_hint.as_deref()?;
    let remaining_days = match identity.plan_expires_at {
        None => REMAINING_DAYS_PERMANENT,
        Some(expires_at) => {
            let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
            // 负值（已过期）也按整天数向下取整，前端展示为 0 或负数即可。
            seconds.div_euclid(86_400)
        }
    };
    ExternalIdentityExtension::try_new(
        SUBSCRIPTION_EXTENSION_NAMESPACE.to_owned(),
        ExtensionVersion::Number(1),
        OffsetDateTime::now_utc(),
        vec![
            ExtensionField {
                key: "uid".to_owned(),
                label: "Subject 标识".to_owned(),
                field_type: "text".to_owned(),
                value: serde_json::Value::String(hint.to_owned()),
            },
            ExtensionField {
                key: "remaining_days".to_owned(),
                label: if remaining_days == REMAINING_DAYS_PERMANENT {
                    "剩余天数（-1 = 永久有效）".to_owned()
                } else {
                    "剩余天数".to_owned()
                },
                field_type: "duration_days".to_owned(),
                value: serde_json::Value::from(remaining_days),
            },
        ],
    )
}

/// 把运行时条目追加到持久化 JSONB 之后。持久化内容损坏（非数组）时整体
/// 重建为只含运行时条目的数组：坏数据不该让整个列表接口失败。
fn append_extension(
    persisted: &serde_json::Value,
    extension: ExternalIdentityExtension,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut items: Vec<serde_json::Value> = match persisted {
        serde_json::Value::Array(items) => items.clone(),
        serde_json::Value::Null => Vec::new(),
        _ => Vec::new(),
    };
    items.push(serde_json::to_value(extension)?);
    Ok(serde_json::Value::Array(items))
}

/// 为一批身份组装并追加订阅扩展。持久化条目在前，运行时条目在后：
/// JSONB 里的内容是绑定/同步时固化的快照，订阅状态每次读取都重新计算，
/// 顺序反映这个差异。
pub fn append_subscription_extensions(
    identities: &mut [super::repository::LinkedExternalIdentity],
) -> Result<(), serde_json::Error> {
    for identity in identities {
        if let Some(extension) = subscription_extension(identity) {
            identity.extensions = append_extension(&identity.extensions, extension)?;
        }
    }
    Ok(())
}
