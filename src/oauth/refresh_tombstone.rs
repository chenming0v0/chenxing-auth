//! Refresh Token 的墓碑（tombstone）领域类型。
//!
//! 墓碑是「这个 token 曾经合法存在过」的证据。token 主键被删除后，`find`
//! 只能回答「现在没有」，无法区分未知 token 与已消费凭据的重放；墓碑补上
//! 这个信息，并携带定位撤销单元所需的 `family_id`。
//!
//! 从 `refresh_store.rs` 拆出来是为了让存储实现、撤销实现和这里的判定各自
//! 保持在可审查的长度内。

use serde::{Deserialize, Serialize};

use super::refresh::RefreshToken;

/// 墓碑状态。
///
/// `Consumed` 表示 token 被正常单次消费/轮换。再次提交同一个值就是重放，
/// 没有例外：`Consumed` 墓碑一律触发 family 撤销（RFC 9700 §4.14.2）。
///
/// `ExplicitRevoke` 表示客户端主动撤销，`FamilyRevoked` 表示该 family 已经
/// 完成撤销。两者都只说明凭据已死，不是新的泄露信号，不再触发撤销动作。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneState {
    #[default]
    Consumed,
    ExplicitRevoke,
    FamilyRevoked,
}

/// 墓碑载荷（存入 Redis，供重放检测时校验 client_id 和消费状态）。
///
/// 墓碑携带 `client_id` 是为了防范跨客户端 DoS：若不校验，
/// Client A 提交 Client B 已消费的 token，就能触发 B 的 family 撤销，
/// 把重放防御变成摧毁合法凭据的工具（Issue #110）。`recorded_at` 只保存
/// Unix 秒级时间戳，不保存 refresh token 原值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub family_id: String,
    pub client_id: String,
    pub user_id: String,
    #[serde(default)]
    pub state: TombstoneState,
    #[serde(default)]
    pub recorded_at: i64,
}

impl Tombstone {
    pub(super) fn for_token(token: &RefreshToken, state: TombstoneState) -> Self {
        Self {
            family_id: token.family_id.clone(),
            client_id: token.client_id.clone(),
            user_id: token.user_id.clone(),
            state,
            recorded_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    pub(super) fn for_family(
        family_id: &str,
        client_id: &str,
        user_id: &str,
        state: TombstoneState,
    ) -> Self {
        Self {
            family_id: family_id.to_owned(),
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            state,
            recorded_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}
