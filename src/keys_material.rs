//! 签名密钥材料的领域结构与规则：材料生命周期、保留窗口、替代者选择。
//!
//! 与磁盘副作用无关的纯领域逻辑集中在这里，`keys.rs` 只保留 `KeyManager`
//! 状态机与协议读路径。子模块（轮换、吊销、持久化）通过 `keys.rs` 的转发
//! 访问这些规则，保证"最近在役"等安全判据只有一份实现。

use std::collections::BTreeMap;

use time::OffsetDateTime;
use zeroize::Zeroizing;

/// RSA 私钥的 PKCS#1 DER 字节。
///
/// Rust 的 drop 只归还内存、不保证擦除内容：`Vec<u8>` 丢弃后私钥字节仍留在堆上，直到被分配器
/// 复用覆盖，期间 coredump、swap 落盘或同进程内存扫描都可能还原出完整私钥。`Zeroizing` 在
/// drop 时原地清零以消除该窗口，所有流经内存的私钥字节都必须用它包装。
pub(super) type PrivateKeyDer = Zeroizing<Vec<u8>>;
#[derive(Clone)]
pub(super) struct KeyMaterial {
    /// `Zeroizing` 的 clone 仍带清零语义，轮换时克隆的旧材料副本也会被擦除。
    pub(super) der: PrivateKeyDer,
    /// 材料诞生的时刻。只在“最近在役”排定时作为次要次序（退役时刻相同或都
    /// 缺失时），不参与保留窗口计算。
    pub(super) created_at: OffsetDateTime,
    /// 停止签发、降级为只验证的时刻。`None` 表示这个 key 仍在役。
    ///
    /// 保留窗口从这里起算而不是从 `created_at` 起算（Issue #298）：在役时长完全
    /// 由运维的轮换节奏决定，可以远超保留窗口，用创建时刻起算会让长期在役的 key
    /// 在轮换那一瞬间就越过窗口，把它最后一刻签发、尚未到 `exp` 的令牌一起作废。
    ///
    /// 不变量：这个字段为 `None` 当且仅当该 key 是 active key。持久化模式下由
    /// `retirement::reconcile` 在目录锁内双向维持，内存模式下由轮换与吊销维持。
    pub(super) retired_at: Option<OffsetDateTime>,
}
/// 手写 `Debug`：派生实现会整段打印私钥 DER，一旦 `KeyMaterial` 被记进日志或断言失败信息，
/// 就等于泄漏签名私钥。（`Zeroizing` 本身也未实现 `Debug`，无法派生。）
impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyMaterial")
            .field("der", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

/// 按“最近在役”选取替代者：吊销 active key 后的替代、kid 文件丢失时采用哪个
/// 材料，都走这一份判断。
///
/// 不能用创建时刻/mtime 作为主判据：磁盘路径上 mtime 可被外部修改（`touch`），
/// 被 touch 的旧 key 会冒充“最新”，被选为吊销后的替代者并清掉退役记录、无限期
/// 重新在役（Issue #318）。退役时刻来自 `retirement` 记录，`touch` 改变不了它；
/// 从未退役（记录缺失，通常是升级前就存在的历史目录或刚切换完的 key）视为最新，
/// 它是最近还在役的那个。
pub(super) fn newest_key_id(materials: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    materials
        .iter()
        .max_by(|(_, a), (_, b)| {
            compare_recency(a.retired_at, a.created_at, b.retired_at, b.created_at)
        })
        .map(|(key_id, _)| key_id.clone())
}

/// 两份材料的“最近在役”次序：退役时刻晚者优先；从未退役视为最新；退役时刻
/// 相同或都缺失时退回创建时刻排定，保证次序确定。
///
/// `T` 是创建时刻的类型：内存快照用 `OffsetDateTime`，恢复路径只读元数据时用
/// `SystemTime`（mtime），判据保持一致。
pub(super) fn compare_recency<T: Ord>(
    a_retired_at: Option<OffsetDateTime>,
    a_created_at: T,
    b_retired_at: Option<OffsetDateTime>,
    b_created_at: T,
) -> std::cmp::Ordering {
    match (a_retired_at, b_retired_at) {
        (Some(a_retired), Some(b_retired)) => a_retired
            .cmp(&b_retired)
            .then_with(|| a_created_at.cmp(&b_created_at)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a_created_at.cmp(&b_created_at),
    }
}

/// 构造一份在役材料。退役时刻由轮换、吊销或磁盘记录后续填入。
pub(super) fn key_material(der: PrivateKeyDer, created_at: OffsetDateTime) -> KeyMaterial {
    KeyMaterial {
        der,
        created_at,
        retired_at: None,
    }
}
