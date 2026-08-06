//! Client 凭据的常量时间校验（Issue #63：消除 client_id 存在性的计时侧信道）。
//!
//! 独立成模块的原因：这里的每一行都在维持「无论 client 是否存在、状态与认证方式
//! 是否合法，都付出相同的 Argon2 计算代价」这一个不变量。它与凭据的签发/匹配是
//! 不同的关注点，混在一个文件里容易在后续改动中被顺手「优化」掉短路语义。

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use std::sync::OnceLock;

use super::generate_client_secret;
use crate::clients::{domain::ClientAuthMethod, repository::StoredClientCredentials};

/// 用于计时填充的虚构请求 secret，当请求不携带 secret 时作为探针输入 Argon2，
/// 保证「无 secret」路径也付出与「有 secret 但错误」路径相同的计算代价。
const DUMMY_SECRET_PROBE: &str = "chenxing-auth-dummy-client-secret-probe";

/// Dummy Argon2 哈希缓存（Issue #63 计时均一化）。
///
/// 与 users::credentials 的已知 bug #124 不同，此处失败时**不缓存空串**：
/// 若 Argon2 或 OsRng 暂时不可用，返回 `None`，调用方回退到空串（快速失败）
/// 并 `tracing::error!` 告警；下次请求仍会重试。
/// 这样确保 DUMMY_CLIENT_SECRET_HASH 中的值永远是合法的 Argon2 PHC 串。
static DUMMY_CLIENT_SECRET_HASH: OnceLock<String> = OnceLock::new();

/// 获取虚构 secret 对应的 Argon2 哈希。
///
/// 首次调用时按需生成并缓存；失败时返回 `None`（不写入缓存，避免 #124）。
/// 虚构哈希来自随机 UUID 明文（调用 `generate_client_secret` 内部相同的参数），
/// 明文**即时丢弃**——攻击者无法预测，所以无法构造「通过哈希验证」的请求。
fn dummy_client_secret_hash() -> Option<&'static str> {
    // 已缓存直接返回
    if let Some(h) = DUMMY_CLIENT_SECRET_HASH.get() {
        return Some(h.as_str());
    }
    // 用随机 UUID 明文生成哈希，并立即丢弃明文：
    // 任何输入（包括 DUMMY_SECRET_PROBE）都无法通过这个哈希的校验，
    // 因此失败路径上的 argon2_ok 恒为 false，不依赖后续 `&` 兜底。
    match generate_client_secret() {
        Ok((_discarded_plaintext, hash)) => {
            // 并发时两线程都可能走到这里，set 失败表示另一线程已写入，使用那个值即可。
            let _ = DUMMY_CLIENT_SECRET_HASH.set(hash);
            DUMMY_CLIENT_SECRET_HASH.get().map(|s| s.as_str())
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to prepare dummy client secret hash");
            None // 不缓存，下次重试
        }
    }
}

/// 检查"廉价策略门"：client 存在 + status active + auth_method 与请求匹配。
///
/// 这些是纯字符串比较，时间可忽略。其结果决定后续选用真实 hash 还是 dummy hash，
/// 但不跳过 Argon2 执行——即使门判定为 false，Argon2 仍然无条件运行。
fn policy_gate_ok(
    requested_method: ClientAuthMethod,
    stored: Option<&StoredClientCredentials>,
) -> bool {
    stored.is_some_and(|s| {
        s.status == "active" && ClientAuthMethod::parse(&s.auth_method) == Some(requested_method)
    })
}

/// 常量时间 Client 凭据校验（Issue #63：消除 client_id 存在性的计时侧信道）。
///
/// # 算法
///
/// ```text
/// 1. 廉价策略门：client 存在 && status active && auth_method 匹配
/// 2. 选 hash：门通 → 用数据库存的 hash；门不通 → 用 dummy hash
/// 3. 选 secret：请求有 secret → 用请求的 secret；无 → 用探针常量
/// 4. 无条件执行一次 Argon2 verify
/// 5. 最终判定：对 ClientAuthMethod::None（公开客户端），secret 有效条件是
///    请求和数据库都不携带 secret（不走 Argon2 路径）；
///    对机密客户端，secret 有效条件是 Argon2 通过 & 请求有 secret & 数据库有 hash。
///    两类结果都用 `&`（按位与，非短路）与策略门 AND，避免短路重新引入时序差异。
/// ```
///
/// # ClientAuthMethod::None（公开客户端）
///
/// 公开客户端（SPA / 移动端）不携带 secret，数据库也不存 hash。
/// 对这类客户端，"凭据是否合法"等价于「请求无 secret 且数据库无 hash」。
/// 为保持时序均一，仍然对 dummy hash 执行一次 Argon2 verify（结果忽略）。
///
/// # 按位与（`&`）vs 短路与（`&&`）
///
/// 最终判定一律使用 `&` 而非 `&&`：即使第一个操作数为 false，后续操作数也会被求值。
/// 若改用 `&&`，当 gate = false 时 secret_ok 被跳过，「不存在的 client」和
/// 「存在但 secret 错」在 decide 阶段耗时出现差异，侧信道复现。
/// clippy::needless_bitwise_bool / clippy::nonminimal_bool 的建议此处必须忽略。
#[allow(clippy::needless_bitwise_bool, clippy::nonminimal_bool)]
pub fn verify_client_credentials_constant_time(
    requested_method: ClientAuthMethod,
    client_secret: Option<&str>,
    stored: Option<&StoredClientCredentials>,
) -> bool {
    let gate = policy_gate_ok(requested_method, stored);

    // 选取哈希：门通时用数据库 hash，门不通时用 dummy hash 保持 Argon2 代价。
    // 门通但 stored_hash 为 None（机密客户端缺 hash，数据异常）同样用 dummy。
    let stored_hash_str: Option<&str> = if gate {
        stored.and_then(|s| s.client_secret_hash.as_deref())
    } else {
        None
    };
    let hash_for_verify: &str = match stored_hash_str {
        Some(h) => h,
        None => dummy_client_secret_hash().unwrap_or(""),
    };

    // 选取探针：请求携带 secret 则用请求值；否则用探针常量（不能通过任何真实 hash 的验证）。
    let secret_for_verify: &str = client_secret.unwrap_or(DUMMY_SECRET_PROBE);

    // 无条件执行一次 Argon2 verify —— 这是本函数的核心：
    // 无论 client 是否存在、status / method 是否合法，都付出相同的 Argon2 计算代价，
    // 使攻击者无法通过响应时间区分「client_id 不存在」与「secret 错误」。
    let argon2_ok = match PasswordHash::new(hash_for_verify) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret_for_verify.as_bytes(), &parsed)
            .is_ok(),
        // hash_for_verify 为空串（dummy 生成失败的极端降级）：快速返回 false，安全
        Err(_) => false,
    };

    // 公开客户端的 secret 合法条件：请求无 secret 且数据库无 hash（两者都为 None）。
    // 机密客户端的 secret 合法条件：Argon2 通过 & 请求有 secret & 数据库有 hash。
    //
    // 全部用 `&`（按位与，非短路）连接，确保所有操作数均被求值，
    // 避免 `&&` 短路在 argon2_ok = false 时跳过后续求值，重新引入时序差异（Issue #63）。
    let secret_ok: bool = match requested_method {
        ClientAuthMethod::None => {
            // 公开客户端：Argon2 结果忽略，仅校验「双方都无 secret/hash」
            let no_secret = client_secret.is_none();
            let no_stored_hash = stored
                .and_then(|s| s.client_secret_hash.as_deref())
                .is_none();
            no_secret & no_stored_hash
        }
        ClientAuthMethod::Basic | ClientAuthMethod::Post => {
            // 机密客户端：Argon2 通过 + 请求有 secret + 数据库有 hash 三者缺一不可
            argon2_ok & client_secret.is_some() & stored_hash_str.is_some()
        }
    };

    // 最终用 `&` 将策略门与 secret 合法性合并。
    // 即使 gate = false，secret_ok 已完整求值（Argon2 已运行），时序均一。
    gate & secret_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(auth_method: &str, status: &str, hash: Option<&str>) -> StoredClientCredentials {
        StoredClientCredentials {
            client_secret_hash: hash.map(|s| s.to_owned()),
            auth_method: auth_method.to_owned(),
            status: status.to_owned(),
        }
    }

    #[test]
    fn dummy_client_secret_hash_returns_stable_argon2_hash() {
        let hash1 = super::dummy_client_secret_hash().expect("dummy hash should generate");
        let hash2 = super::dummy_client_secret_hash().expect("should cache");
        assert!(hash1.starts_with("$argon2"));
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn policy_gate_decisions() {
        // client 不存在
        assert!(!super::policy_gate_ok(ClientAuthMethod::Basic, None));
        // status disabled
        assert!(!super::policy_gate_ok(
            ClientAuthMethod::Basic,
            Some(&stored("client_secret_basic", "disabled", Some("h")))
        ));
        // auth_method 不匹配
        assert!(!super::policy_gate_ok(
            ClientAuthMethod::Post,
            Some(&stored("client_secret_basic", "active", Some("h")))
        ));
        // 正常通过
        assert!(super::policy_gate_ok(
            ClientAuthMethod::Basic,
            Some(&stored("client_secret_basic", "active", Some("h")))
        ));
    }

    #[test]
    fn constant_time_verify_rejects_gate_failures() {
        // client 不存在
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::Basic,
            Some("s"),
            None
        ));
        // status disabled
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::Basic,
            Some("s"),
            Some(&stored("client_secret_basic", "disabled", Some("h")))
        ));
        // method 不匹配
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::Post,
            Some("s"),
            Some(&stored("client_secret_basic", "active", Some("h")))
        ));
    }

    #[test]
    fn constant_time_verify_accepts_public_client_without_secret() {
        assert!(verify_client_credentials_constant_time(
            ClientAuthMethod::None,
            None,
            Some(&stored("none", "active", None))
        ));
    }

    #[test]
    fn constant_time_verify_rejects_public_client_edge_cases() {
        // 请求携带了不该有的 secret
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::None,
            Some("unexpected"),
            Some(&stored("none", "active", None))
        ));
        // 数据库遗留了 hash（配置错误），fail closed
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::None,
            None,
            Some(&stored("none", "active", Some("$argon2...")))
        ));
    }

    #[test]
    fn constant_time_verify_accepts_correct_confidential_secret() {
        // 生成真实 Argon2 哈希（昂贵操作，覆盖完整路径所必需）
        let (plaintext, hash) = generate_client_secret().expect("generate secret");
        let s = stored("client_secret_basic", "active", Some(&hash));
        assert!(verify_client_credentials_constant_time(
            ClientAuthMethod::Basic,
            Some(&plaintext),
            Some(&s)
        ));
    }

    #[test]
    fn constant_time_verify_rejects_wrong_or_missing_secret() {
        let (_, hash) = generate_client_secret().expect("generate secret");
        let s = stored("client_secret_basic", "active", Some(&hash));
        // 错误 secret
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::Basic,
            Some("cxs_wrong"),
            Some(&s)
        ));
        // 缺少 secret
        assert!(!verify_client_credentials_constant_time(
            ClientAuthMethod::Basic,
            None,
            Some(&s)
        ));
    }
}
