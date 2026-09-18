//! Account Provider v1 快照根的严格解析。
//!
//! 快照是消费方唯一按协议渲染的数据面。这里只暴露已校验的强类型，不向上层泄漏
//! `serde_json::Value` 树；未知顶层字段按前向兼容忽略，未知 `fields[].type` 真正
//! 丢弃（不按对象渲染），未知 `subscription.kind` 直接失败，绝不降级成
//! `permanent` / `none`。

use serde_json::{Map, Value};
use url::Url;

use super::error::ProtocolError;
use super::scalar::{
    Issuer, SafeNumber, UtcTime, bounded_string, parse_https_url, parse_json_limited,
    parse_seconds, parse_utc, required, required_string,
};

pub const SNAPSHOT_SCHEMA_VERSION: &str = "1";
pub const MAX_SNAPSHOT_FIELDS: usize = 64;

/// 账号状态。未知取值不是合法快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Disabled,
    Unknown,
}

impl AccountStatus {
    fn parse(value: &str) -> Result<Self, ProtocolError> {
        Ok(match value {
            "active" => Self::Active,
            "disabled" => Self::Disabled,
            "unknown" => Self::Unknown,
            _ => return Err(ProtocolError::InvalidValue("status")),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
}

/// 订阅的判别联合。
///
/// 变体间互斥：`expires_at: null` 这类「键存在但值为空」同样违反互斥，因为协议
/// 要求 `required` 只看键是否存在。`null` 永不表示永久，`0` 也不表示未知。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscription {
    ExpiresAt {
        expires_at: UtcTime,
    },
    Remaining {
        remaining_seconds: u64,
        as_of: UtcTime,
    },
    Permanent,
    None,
    Unknown,
}

impl Subscription {
    fn from_value(value: &Value) -> Result<Self, ProtocolError> {
        let map = value
            .as_object()
            .ok_or(ProtocolError::UnexpectedType("subscription"))?;
        let kind = map
            .get("kind")
            .ok_or(ProtocolError::MissingRequired("subscription.kind"))?
            .as_str()
            .ok_or(ProtocolError::UnexpectedType("subscription.kind"))?;
        match kind {
            "expires_at" => {
                reject_keys(map, &["remaining_seconds", "as_of"])?;
                let expires_at =
                    parse_utc(required(map, "expires_at")?, "subscription.expires_at")?;
                Ok(Self::ExpiresAt { expires_at })
            }
            "remaining" => {
                reject_keys(map, &["expires_at"])?;
                let remaining_seconds = parse_seconds(
                    required(map, "remaining_seconds")?,
                    "subscription.remaining_seconds",
                )?;
                let as_of = parse_utc(required(map, "as_of")?, "subscription.as_of")?;
                Ok(Self::Remaining {
                    remaining_seconds,
                    as_of,
                })
            }
            "permanent" | "none" | "unknown" => {
                reject_keys(map, &["expires_at", "remaining_seconds", "as_of"])?;
                Ok(match kind {
                    "permanent" => Self::Permanent,
                    "none" => Self::None,
                    _ => Self::Unknown,
                })
            }
            _ => Err(ProtocolError::UnknownSubscriptionKind),
        }
    }
}

fn reject_keys(map: &Map<String, Value>, keys: &[&'static str]) -> Result<(), ProtocolError> {
    if keys.iter().any(|key| map.contains_key(*key)) {
        return Err(ProtocolError::SubscriptionFieldConflict);
    }
    Ok(())
}

/// `fields[].value` 的已知类型。未知 `type` 的条目在解析时被丢弃，不进入此枚举。
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Text(String),
    Number(SafeNumber),
    Boolean(bool),
    Status(String),
    DateTime(UtcTime),
    Duration(u64),
    Url(Url),
}

/// 已校验的展示字段。
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotField {
    pub key: String,
    pub label: String,
    pub value: FieldValue,
}

/// 已校验的快照根。
#[derive(Debug, Clone, PartialEq)]
pub struct AccountSnapshot {
    pub issuer: Issuer,
    pub uid: String,
    pub account: String,
    pub name: Option<String>,
    pub status: AccountStatus,
    pub subscription: Subscription,
    pub fields: Vec<SnapshotField>,
    pub fetched_at: UtcTime,
}

impl AccountSnapshot {
    /// 从响应字节解析，强制的 128 KiB 上限在 [`parse_json_limited`] 内执行。
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_value(&parse_json_limited(bytes)?)
    }

    pub fn from_value(value: &Value) -> Result<Self, ProtocolError> {
        let map = value.as_object().ok_or(ProtocolError::NotAnObject)?;
        let schema_version = required_string(map, "schema_version", 1, 16)?;
        if schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidValue("schema_version"));
        }
        let issuer = Issuer::parse(&required_string(map, "issuer", 1, 255)?)?;
        let uid = required_string(map, "uid", 1, 255)?;
        let account = required_string(map, "account", 1, 128)?;
        let name = match required(map, "name")? {
            Value::Null => None,
            Value::String(text) => {
                if text.len() > 128 {
                    return Err(ProtocolError::ByteLimitExceeded("name"));
                }
                Some(text.clone())
            }
            _ => return Err(ProtocolError::UnexpectedType("name")),
        };
        let status = AccountStatus::parse(&required_string(map, "status", 1, 16)?)?;
        let subscription = Subscription::from_value(required(map, "subscription")?)?;
        let fields = parse_fields(required(map, "fields")?)?;
        let fetched_at = parse_utc(required(map, "fetched_at")?, "fetched_at")?;
        Ok(Self {
            issuer,
            uid,
            account,
            name,
            status,
            subscription,
            fields,
            fetched_at,
        })
    }
}

/// `snapshot.schema.json` 的 `fields[].key` pattern：小写字母开头，后跟小写字母、
/// 数字、`_`、`.`、`-`。
fn is_valid_field_key(key: &str) -> bool {
    let mut characters = key.chars();
    match characters.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    characters.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | '.' | '-')
    })
}

fn parse_fields(value: &Value) -> Result<Vec<SnapshotField>, ProtocolError> {
    let entries = value
        .as_array()
        .ok_or(ProtocolError::UnexpectedType("fields"))?;
    if entries.len() > MAX_SNAPSHOT_FIELDS {
        return Err(ProtocolError::TooManyFields);
    }
    let mut fields = Vec::with_capacity(entries.len());
    let mut seen: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let map = entry
            .as_object()
            .ok_or(ProtocolError::UnexpectedType("fields[]"))?;
        // 公用的 key/label/type 与 key 唯一性先于 type 分派校验：即使该条目之后
        // 因未知 type 被丢弃，它的 key 仍占用唯一性名额，也必须符合 pattern。
        let key = bounded_string(required(map, "key")?, "field.key", 1, 128)?;
        if !is_valid_field_key(&key) {
            return Err(ProtocolError::InvalidValue("field.key"));
        }
        if seen.iter().any(|existing| existing == &key) {
            return Err(ProtocolError::DuplicateFieldKey);
        }
        seen.push(key.clone());
        let label = bounded_string(required(map, "label")?, "field.label", 1, 256)?;
        let type_name = bounded_string(required(map, "type")?, "field.type", 1, 64)?;
        // 已知 type 才继续解析 value；未知 type 按协议丢弃，绝不按对象渲染。
        let Some(field_value) = parse_known_field_value(required(map, "value")?, &type_name)?
        else {
            continue;
        };
        fields.push(SnapshotField {
            key,
            label,
            value: field_value,
        });
    }
    Ok(fields)
}

/// 解析已知 `type` 的 value；返回 `None` 表示 type 未知，调用方丢弃该 field。
fn parse_known_field_value(
    value: &Value,
    type_name: &str,
) -> Result<Option<FieldValue>, ProtocolError> {
    let parsed = match type_name {
        "text" => FieldValue::Text(bounded_string(value, "field.value", 0, 512)?),
        "status" => FieldValue::Status(bounded_string(value, "field.value", 0, 64)?),
        "boolean" => FieldValue::Boolean(
            value
                .as_bool()
                .ok_or(ProtocolError::UnexpectedType("field.value"))?,
        ),
        "number" => FieldValue::Number(SafeNumber::parse(value, "field.value")?),
        "datetime" => FieldValue::DateTime(parse_utc(value, "field.value")?),
        "duration" => FieldValue::Duration(parse_seconds(value, "field.value")?),
        "url" => FieldValue::Url(parse_https_url(value, "field.value")?),
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

/// 已校验快照的规范 JSON 重建，只用于令牌包加密落库。
impl AccountSnapshot {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "issuer": self.issuer.as_str(),
            "uid": self.uid,
            "account": self.account,
            "name": self.name,
            "status": self.status.as_str(),
            "subscription": self.subscription.to_value(),
            "fields": self.fields.iter().map(SnapshotField::to_value).collect::<Vec<_>>(),
            "fetched_at": self.fetched_at.to_rfc3339(),
        })
    }
}

impl Subscription {
    fn to_value(self) -> Value {
        match self {
            Self::ExpiresAt { expires_at } => serde_json::json!({
                "kind": "expires_at",
                "expires_at": expires_at.to_rfc3339(),
            }),
            Self::Remaining {
                remaining_seconds,
                as_of,
            } => serde_json::json!({
                "kind": "remaining",
                "remaining_seconds": remaining_seconds,
                "as_of": as_of.to_rfc3339(),
            }),
            Self::Permanent => serde_json::json!({ "kind": "permanent" }),
            Self::None => serde_json::json!({ "kind": "none" }),
            Self::Unknown => serde_json::json!({ "kind": "unknown" }),
        }
    }
}

impl SnapshotField {
    fn to_value(&self) -> Value {
        serde_json::json!({
            "key": self.key,
            "label": self.label,
            "type": self.value.type_name(),
            "value": self.value.to_value(),
        })
    }
}

impl FieldValue {
    fn type_name(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Number(_) => "number",
            Self::Boolean(_) => "boolean",
            Self::Status(_) => "status",
            Self::DateTime(_) => "datetime",
            Self::Duration(_) => "duration",
            Self::Url(_) => "url",
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Text(text) | Self::Status(text) => Value::String(text.clone()),
            Self::Number(number) => serde_json::json!(number.get()),
            Self::Boolean(flag) => Value::Bool(*flag),
            Self::DateTime(time) => Value::String(time.to_rfc3339()),
            Self::Duration(seconds) => serde_json::json!(seconds),
            Self::Url(url) => Value::String(url.as_str().to_owned()),
        }
    }
}
