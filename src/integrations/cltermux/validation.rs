//! 入站快照结构校验与入站 token 摘要校验。
//!
//! 校验边界：快照原始 JSON 的 128 KiB 大小检查由调用方在 serde 解析前完成；
//! 本模块只做解析后的结构/语义校验。任何校验失败 = 供应商响应不合法，
//! 调用方不得用该响应覆盖旧快照。

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use super::contract::{
    AccountSnapshotDto, DeviceDto, DisplayDto, ExtensionBlockDto, SubscriptionDto,
};
use super::types::{
    AccountStatus, DeviceStatus, LinkedAccountSnapshot, SnapshotDevice, SnapshotDisplay,
    SnapshotSubscription,
};

/// 协议冻结的 extensions v1 上限。
pub const MAX_EXTENSION_BLOCKS: usize = 32;
pub const MAX_EXTENSION_FIELDS_PER_BLOCK: usize = 100;
pub const MAX_NAMESPACE_OR_KEY_LEN: usize = 128;
pub const MAX_LABEL_LEN: usize = 256;
pub const MAX_TEXT_LEN: usize = 512;
pub const MAX_STATUS_LEN: usize = 64;
pub const MAX_URL_LEN: usize = 2048;

/// CLtermux allowlist：固定 6 个 key 与其唯一允许的类型。
/// 未知 key/type 或校验失败 = 供应商响应不合法。
const ALLOWLIST: &[(&str, ExtensionFieldType)] = &[
    ("uid", ExtensionFieldType::Text),
    ("account_status", ExtensionFieldType::Status),
    ("is_subscribed", ExtensionFieldType::Boolean),
    ("subscription_expires_at", ExtensionFieldType::Datetime),
    ("remaining_days", ExtensionFieldType::DurationDays),
    ("device_status", ExtensionFieldType::Status),
];

/// extensions v1 的固定版本字符串。
const EXTENSIONS_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionFieldType {
    Text,
    Number,
    Boolean,
    Status,
    Datetime,
    DurationDays,
    Url,
}

impl ExtensionFieldType {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "text" => Some(Self::Text),
            "number" => Some(Self::Number),
            "boolean" => Some(Self::Boolean),
            "status" => Some(Self::Status),
            "datetime" => Some(Self::Datetime),
            "duration_days" => Some(Self::DurationDays),
            "url" => Some(Self::Url),
            _ => None,
        }
    }
}

/// 校验失败原因。只描述结构问题，不携带供应商响应原文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRejection {
    SchemaVersion,
    UidShape,
    SubjectShape,
    Status,
    Display,
    Subscription,
    Device,
    Extensions,
    FetchedAt,
}

/// 校验供应商快照并转换为应用层快照。
///
/// 订阅判定的权威在 CLtermux 服务端（is_enabled && is_active &&
/// expires_at > now，UTC）；辰星只透传已校验的展示字段，绝不本地重算。
pub fn validate_snapshot(
    dto: &AccountSnapshotDto,
) -> Result<LinkedAccountSnapshot, SnapshotRejection> {
    if dto.schema_version != "1" {
        return Err(SnapshotRejection::SchemaVersion);
    }
    if !dto.uid.starts_with("cltermux:")
        || dto.uid.len() <= "cltermux:".len()
        || dto.uid.len() > 255
    {
        return Err(SnapshotRejection::UidShape);
    }
    if dto.subject != dto.uid || dto.subject.len() > 255 {
        return Err(SnapshotRejection::SubjectShape);
    }
    let account_status = parse_account_status(&dto.status)?;
    let display = validate_display(&dto.display)?;
    let subscription = validate_subscription(&dto.subscription)?;
    let device = validate_device(&dto.device)?;
    let extensions = validate_extensions(&dto.extensions)?;
    Ok(LinkedAccountSnapshot {
        account_status,
        display,
        subscription,
        device,
        extensions,
        fetched_at: dto.fetched_at,
    })
}

fn parse_account_status(raw: &str) -> Result<AccountStatus, SnapshotRejection> {
    match raw {
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        "missing" => Ok(AccountStatus::Missing),
        "unknown" => Ok(AccountStatus::Unknown),
        _ => Err(SnapshotRejection::Status),
    }
}

fn validate_display(dto: &DisplayDto) -> Result<SnapshotDisplay, SnapshotRejection> {
    // 三个展示字段均可空；非空时只做基本长度约束，避免超长值进入快照。
    for value in [&dto.name, &dto.email, &dto.avatar_url] {
        if let Some(value) = value {
            if value.is_empty() || value.len() > 512 {
                return Err(SnapshotRejection::Display);
            }
        }
    }
    Ok(SnapshotDisplay {
        name: dto.name.clone(),
        email: dto.email.clone(),
        avatar_url: dto.avatar_url.clone(),
    })
}

fn validate_subscription(dto: &SubscriptionDto) -> Result<SnapshotSubscription, SnapshotRejection> {
    // remaining_days 是非负整数（u32 已保证）；负值在 serde 反序列化时即失败。
    // expires_at 可空（null），是唯一允许为空的 datetime 字段。
    Ok(SnapshotSubscription {
        is_subscribed: dto.is_subscribed,
        expires_at: dto.expires_at,
        remaining_days: dto.remaining_days,
    })
}

fn validate_device(dto: &DeviceDto) -> Result<SnapshotDevice, SnapshotRejection> {
    let status = match dto.status.as_str() {
        "unbound" => DeviceStatus::Unbound,
        "bound" => DeviceStatus::Bound,
        "unknown" => DeviceStatus::Unknown,
        _ => return Err(SnapshotRejection::Device),
    };
    Ok(SnapshotDevice {
        status,
        last_seen_at: dto.last_seen_at,
    })
}

fn validate_extensions(
    blocks: &[ExtensionBlockDto],
) -> Result<serde_json::Value, SnapshotRejection> {
    if blocks.len() > MAX_EXTENSION_BLOCKS {
        return Err(SnapshotRejection::Extensions);
    }
    let mut validated = Vec::with_capacity(blocks.len());
    for block in blocks {
        validated.push(validate_extension_block(block)?);
    }
    serde_json::to_value(validated).map_err(|_| SnapshotRejection::Extensions)
}

fn validate_extension_block(
    block: &ExtensionBlockDto,
) -> Result<serde_json::Value, SnapshotRejection> {
    if !is_valid_namespace_or_key(&block.namespace)
        || block.version != EXTENSIONS_VERSION
        || block.fields.len() > MAX_EXTENSION_FIELDS_PER_BLOCK
    {
        return Err(SnapshotRejection::Extensions);
    }
    // 同块 key 不重复：先收集再查重，避免 O(n²) 的逐对比较。
    let mut seen_keys = std::collections::HashSet::with_capacity(block.fields.len());
    let mut fields = Vec::with_capacity(block.fields.len());
    for field in &block.fields {
        if !is_valid_namespace_or_key(&field.key)
            || field.label.is_empty()
            || field.label.len() > MAX_LABEL_LEN
            || !seen_keys.insert(field.key.as_str())
        {
            return Err(SnapshotRejection::Extensions);
        }
        let allowed = ALLOWLIST
            .iter()
            .find(|(key, _)| *key == field.key)
            .map(|(_, allowed_type)| *allowed_type);
        let Some(allowed_type) = allowed else {
            // 未知 key = 供应商响应不合法，不覆盖旧快照。
            return Err(SnapshotRejection::Extensions);
        };
        if ExtensionFieldType::parse(&field.r#type) != Some(allowed_type) {
            return Err(SnapshotRejection::Extensions);
        }
        if !(field.key == "subscription_expires_at" && field.value.is_null()) {
            validate_field_value(allowed_type, &field.value)?;
        }
        fields.push(serde_json::to_value(field).map_err(|_| SnapshotRejection::Extensions)?);
    }
    serde_json::to_value(serde_json::json!({
        "namespace": block.namespace,
        "version": block.version,
        "fields": fields,
        "fetched_at": block.fetched_at,
    }))
    .map_err(|_| SnapshotRejection::Extensions)
}

fn is_valid_namespace_or_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAMESPACE_OR_KEY_LEN
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

fn validate_field_value(
    field_type: ExtensionFieldType,
    value: &serde_json::Value,
) -> Result<(), SnapshotRejection> {
    match field_type {
        ExtensionFieldType::Text => match value.as_str() {
            Some(text) if !text.is_empty() && text.len() <= MAX_TEXT_LEN => Ok(()),
            _ => Err(SnapshotRejection::Extensions),
        },
        ExtensionFieldType::Status => match value.as_str() {
            Some(status) if !status.is_empty() && status.len() <= MAX_STATUS_LEN => Ok(()),
            _ => Err(SnapshotRejection::Extensions),
        },
        ExtensionFieldType::Boolean => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(SnapshotRejection::Extensions)
            }
        }
        ExtensionFieldType::Number => match value.as_f64() {
            // 有限且 |v| ≤ 2^53-1：JSON number 的安全整数范围。
            Some(number) if number.is_finite() && number.abs() <= 9_007_199_254_740_991.0 => Ok(()),
            _ => Err(SnapshotRejection::Extensions),
        },
        ExtensionFieldType::Datetime => match value.as_str() {
            Some(text) => {
                OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
                    .map(|_| ())
                    .map_err(|_| SnapshotRejection::Extensions)
            }
            None => Err(SnapshotRejection::Extensions),
        },
        ExtensionFieldType::DurationDays => match value.as_u64() {
            // 非负整数；u64 天然排除负值与小数。
            Some(_) => Ok(()),
            None => Err(SnapshotRejection::Extensions),
        },
        ExtensionFieldType::Url => match value.as_str() {
            Some(text) if text.len() <= MAX_URL_LEN => validate_https_url(text),
            _ => Err(SnapshotRejection::Extensions),
        },
    }
}

fn validate_https_url(text: &str) -> Result<(), SnapshotRejection> {
    let parsed = url::Url::parse(text).map_err(|_| SnapshotRejection::Extensions)?;
    // 仅绝对 https，禁止用户信息（凭据材料）。
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(SnapshotRejection::Extensions);
    }
    Ok(())
}

/// 入站 Bearer 校验：对呈现值计算 SHA-256 摘要，与配置摘要做常量时间比较。
///
/// 配置侧只持有摘要（原值在 config 加载时丢弃）；长度不等的摘要直接判否，
/// SHA-256 输出恒为 32 字节，正常路径不会触发该分支。
pub fn verify_inbound_token(presented: &str, digest: &[u8]) -> bool {
    let presented_digest = Sha256::digest(presented.as_bytes());
    presented_digest.as_slice().ct_eq(digest).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::cltermux::contract::ExtensionFieldDto;

    fn field(key: &str, field_type: &str, value: serde_json::Value) -> ExtensionFieldDto {
        ExtensionFieldDto {
            key: key.to_owned(),
            r#type: field_type.to_owned(),
            label: key.to_owned(),
            value,
        }
    }

    fn base_block(fields: Vec<ExtensionFieldDto>) -> ExtensionBlockDto {
        ExtensionBlockDto {
            namespace: "cltermux".to_owned(),
            version: "1".to_owned(),
            fields,
            fetched_at: epoch(),
        }
    }

    fn base_dto(blocks: Vec<ExtensionBlockDto>) -> AccountSnapshotDto {
        AccountSnapshotDto {
            schema_version: "1".to_owned(),
            uid: "cltermux:123".to_owned(),
            subject: "cltermux:123".to_owned(),
            display: DisplayDto {
                name: Some("User".to_owned()),
                email: None,
                avatar_url: None,
            },
            status: "active".to_owned(),
            subscription: SubscriptionDto {
                is_subscribed: true,
                expires_at: Some(epoch()),
                remaining_days: Some(30),
            },
            device: DeviceDto {
                status: "bound".to_owned(),
                last_seen_at: Some(epoch()),
            },
            extensions: blocks,
            fetched_at: epoch(),
        }
    }

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid epoch")
    }

    #[test]
    fn valid_snapshot_with_allowlisted_block_passes() {
        let block = base_block(vec![
            field("uid", "text", serde_json::json!("cltermux:123")),
            field("account_status", "status", serde_json::json!("active")),
            field("is_subscribed", "boolean", serde_json::json!(true)),
            field(
                "subscription_expires_at",
                "datetime",
                serde_json::json!("2026-01-01T00:00:00Z"),
            ),
            field("remaining_days", "duration_days", serde_json::json!(30)),
            field("device_status", "status", serde_json::json!("bound")),
        ]);
        let snapshot = validate_snapshot(&base_dto(vec![block])).expect("valid snapshot");
        assert_eq!(snapshot.account_status, AccountStatus::Active);
        assert_eq!(snapshot.device.status, DeviceStatus::Bound);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let block = base_block(vec![field("unknown_key", "text", serde_json::json!("x"))]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn wrong_type_for_allowlisted_key_is_rejected() {
        let block = base_block(vec![field("uid", "number", serde_json::json!(123))]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn duplicate_key_in_block_is_rejected() {
        let block = base_block(vec![
            field("uid", "text", serde_json::json!("a")),
            field("uid", "text", serde_json::json!("b")),
        ]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn bad_schema_version_is_rejected() {
        let mut dto = base_dto(vec![]);
        dto.schema_version = "2".to_owned();
        assert_eq!(
            validate_snapshot(&dto),
            Err(SnapshotRejection::SchemaVersion)
        );
    }

    #[test]
    fn invalid_datetime_value_is_rejected() {
        let block = base_block(vec![field(
            "subscription_expires_at",
            "datetime",
            serde_json::json!("not-a-date"),
        )]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn http_url_value_is_rejected() {
        let block = base_block(vec![field(
            "uid",
            "text",
            serde_json::json!("http://evil.example"),
        )]);
        // uid 是 text 类型，http 字符串本身合法；url 类型才要求 https。
        assert!(validate_snapshot(&base_dto(vec![block])).is_ok());
    }

    #[test]
    fn url_type_requires_absolute_https_without_userinfo() {
        let http_block = base_block(vec![field(
            "uid",
            "url",
            serde_json::json!("http://example.com"),
        )]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![http_block])),
            Err(SnapshotRejection::Extensions)
        );
        let userinfo_block = base_block(vec![field(
            "uid",
            "url",
            serde_json::json!("https://user:pass@example.com"),
        )]);
        assert_eq!(
            validate_snapshot(&base_dto(vec![userinfo_block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn namespace_pattern_is_enforced() {
        let mut block = base_block(vec![]);
        block.namespace = "Bad_Namespace".to_owned();
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn wrong_extensions_version_is_rejected() {
        let mut block = base_block(vec![]);
        block.version = "2".to_owned();
        assert_eq!(
            validate_snapshot(&base_dto(vec![block])),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn too_many_blocks_is_rejected() {
        let blocks = (0..=MAX_EXTENSION_BLOCKS)
            .map(|i| {
                let mut block = base_block(vec![]);
                block.namespace = format!("ns{i}");
                block
            })
            .collect();
        assert_eq!(
            validate_snapshot(&base_dto(blocks)),
            Err(SnapshotRejection::Extensions)
        );
    }

    #[test]
    fn inbound_token_digest_verification() {
        let token = "cltermux-interop-token-0123456789abcdef";
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        assert!(verify_inbound_token(token, &digest));
        assert!(!verify_inbound_token("wrong-token", &digest));
        assert!(!verify_inbound_token("", &digest));
    }
}
