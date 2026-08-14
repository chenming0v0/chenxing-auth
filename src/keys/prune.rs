//! 退役保留窗口：退役时刻的单调性、窗口判断与按窗口裁剪。
//!
//! 保留窗口的正确起点是密钥停止签发的时刻，不是它被创建的时刻（Issue #298）；
//! 窗口关闭判断还必须容忍跨实例时钟偏差（Issue #316），否则时钟偏快的实例会在
//! 真实窗口结束前删除共享密钥文件。本模块是“哪些 key 过期了”的唯一判断点：
//! 调用方用 `prune_materials` 的返回值删除对应的磁盘文件，内存与磁盘不会各算
//! 一遍（过去磁盘侧用文件 mtime 独立判断，与内存判据不同）。

use std::{collections::BTreeMap, time::Duration};

use time::{Duration as TimeDuration, OffsetDateTime};

use super::KeyMaterial;

/// 把某个 `kid` 标记为已退役，返回生效的退役时刻。
///
/// 已有退役时刻时保持不变并原样返回：窗口起点必须单调，否则重复轮换或重复加载
/// 会不断把它往后推，旧公钥永远不下线。调用方用返回值落盘，因此内存与磁盘写的
/// 始终是同一个时刻。
pub(super) fn mark_retired(
    materials: &mut BTreeMap<String, KeyMaterial>,
    key_id: &str,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let material = materials.get_mut(key_id)?;
    Some(*material.retired_at.get_or_insert(now))
}

/// 按保留窗口裁剪已退役的密钥材料，返回被移除的 `kid`。
///
/// active key 无论多旧都保留：它仍在签发。调用方用返回值删除对应的磁盘文件，
/// 因此“哪些 key 过期了”只在这里判断一次。
///
/// 不区分持久化模式和纯内存模式（Issue #285）：保留窗口是“旧公钥还要能验多久”
/// 这条协议约束，与材料存在硬盘上还是只存在内存里无关。
pub(super) fn prune_materials(
    active_key_id: &str,
    materials: &mut BTreeMap<String, KeyMaterial>,
    retention: Duration,
    skew_allowance: Duration,
    now: OffsetDateTime,
) -> Vec<String> {
    let expired: Vec<String> = materials
        .iter()
        .filter(|(key_id, material)| {
            key_id.as_str() != active_key_id
                && !retirement_window_open_at(material.retired_at, retention, skew_allowance, now)
        })
        .map(|(key_id, _)| key_id.clone())
        .collect();
    for key_id in &expired {
        let _ = materials.remove(key_id);
    }
    expired
}

/// 判断一个已退役的 key 是否仍在保留窗口内。
///
/// 窗口是左闭右开的 `[retired_at, retired_at + retention + skew_allowance)`：
/// 令牌最迟在退役那一刻签发，`exp` 因此不晚于 `retired_at + max_token_ttl`。
/// 配置校验保证 `retention >= max_token_ttl`，所以在窗口右端点移除公钥时，它签发
/// 的令牌均已过期。
///
/// `skew_allowance` 吸收跨实例时钟偏差（Issue #316）：`retired_at` 由退役实例的
/// 时钟写入，`now` 却是当前加载实例自己的时钟。时钟偏快的实例会把
/// `now - retired_at` 算大，若直接按 `retention` 判断，会在真实窗口结束前就判定
/// 过期、删除共享目录里的密钥文件——不可逆且影响所有实例。右端点加上容忍值后，
/// 偏差不超过容忍值的快钟实例只会**晚**删、绝不提前删；慢钟方向由同一个比较天然
/// 覆盖（`now < retired_at` 时差值为负，必然小于右端点），不需要单独的特判分支。
pub(super) fn retirement_window_open_at(
    retired_at: Option<OffsetDateTime>,
    retention: Duration,
    skew_allowance: Duration,
    now: OffsetDateTime,
) -> bool {
    // 尚未退役的 key 不受保留窗口约束。持久化模式下 `retirement::reconcile` 已经
    // 在锁内给每个非 active、非 published-pending 的 key 盖上退役时刻，因此这里
    // 的 `None` 只可能是 active、等待激活的 published key，或内存模式下刚生成的 key。
    let Some(retired_at) = retired_at else {
        return true;
    };
    let Ok(retention) = TimeDuration::try_from(retention) else {
        return true;
    };
    let Ok(skew_allowance) = TimeDuration::try_from(skew_allowance) else {
        return true;
    };
    now - retired_at < retention + skew_allowance
}
