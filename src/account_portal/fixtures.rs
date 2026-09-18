//! 共享夹具的编译期内嵌，供单元测试直接使用。
//!
//! 夹具与 `docs/account-provider-v1/fixtures/` 同源，且产品中立（不含任何
//! 提供方产品名）。测试只读，不修改这些文件。

use serde_json::Value;

pub const METADATA: &str = include_str!("../../docs/account-provider-v1/fixtures/metadata.json");
pub const ACCOUNT_SNAPSHOT: &str =
    include_str!("../../docs/account-provider-v1/fixtures/account-snapshot.json");
pub const SNAPSHOT_UNKNOWN: &str =
    include_str!("../../docs/account-provider-v1/fixtures/snapshot-unknown.json");
pub const LINK_SESSION_REQUEST: &str =
    include_str!("../../docs/account-provider-v1/fixtures/link-session-request.json");
pub const LINK_SESSION_RESPONSE: &str =
    include_str!("../../docs/account-provider-v1/fixtures/link-session-response.json");
pub const REFRESH_REQUEST: &str =
    include_str!("../../docs/account-provider-v1/fixtures/refresh-request.json");
pub const REFRESH_RESPONSE: &str =
    include_str!("../../docs/account-provider-v1/fixtures/refresh-response.json");
pub const REVOKE_REQUEST: &str =
    include_str!("../../docs/account-provider-v1/fixtures/revoke-request.json");
pub const ERROR_ENVELOPE: &str =
    include_str!("../../docs/account-provider-v1/fixtures/error-envelope.json");
pub const INVALID_SUBSCRIPTIONS: &str =
    include_str!("../../docs/account-provider-v1/fixtures/invalid-subscriptions.json");

pub fn value(text: &str) -> Value {
    serde_json::from_str(text).expect("fixture must be valid JSON")
}
