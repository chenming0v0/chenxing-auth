//! Client 凭据的常量时间校验（Issue #63：消除 client_id 存在性的计时侧信道）。
//!
//! 独立成模块的原因：这里的每一行都在维持「无论 client 是否存在、状态与认证方式
//! 是否合法，都付出相同的 Argon2 计算代价」这一个不变量。它与凭据的签发/匹配是
//! 不同的关注点，混在一个文件里容易在后续改动中被顺手「优化」掉短路语义。

use argon2::password_hash::PasswordHash;
use std::sync::OnceLock;

use super::{generate_client_secret, verify_client_secret_blocking};
use crate::clients::{domain::ClientAuthMethod, repository::StoredClientCredentials};

/// 用于计时填充的虚构请求 secret，当请求不携带 secret 时作为探针输入 Argon2，
/// 保证「无 secret」路径也付出与「有 secret 但错误」路径相同的计算代价。
const DUMMY_SECRET_PROBE: &str = "chenxing-auth-dummy-client-secret-probe";

/// 运行期 dummy 哈希生成失败时的合法 PHC 兜底，确保仍然执行 Argon2 verify。
const FALLBACK_DUMMY_CLIENT_SECRET_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Dummy Argon2 哈希缓存（Issue #63 计时均一化）。
///
/// 与 users::credentials 对齐：失败时不缓存空串，而是退回合法 PHC 串，
/// 使计时填充不会因为哈希生成失败而跳过 Argon2。
static DUMMY_CLIENT_SECRET_HASH: OnceLock<String> = OnceLock::new();

/// 获取虚构 secret 对应的 Argon2 哈希。
///
/// 首次调用时按需生成并缓存；失败时退回编译期常量且不写入缓存。
/// 虚构哈希来自随机 UUID 明文（调用 `generate_client_secret` 内部相同的参数），
/// 明文**即时丢弃**——攻击者无法预测，所以无法构造「通过哈希验证」的请求。
fn dummy_client_secret_hash() -> &'static str {
    // 已缓存直接返回
    if let Some(h) = DUMMY_CLIENT_SECRET_HASH.get() {
        return h.as_str();
    }
    // 用随机 UUID 明文生成哈希，并立即丢弃明文：
    // 任何输入（包括 DUMMY_SECRET_PROBE）都无法通过这个哈希的校验，
    // 因此失败路径上的 argon2_ok 恒为 false，不依赖后续 `&` 兜底。
    match generate_client_secret() {
        Ok((_discarded_plaintext, hash)) => {
            // 并发时两线程都可能走到这里，set 失败表示另一线程已写入，使用那个值即可。
            let _ = DUMMY_CLIENT_SECRET_HASH.set(hash);
            DUMMY_CLIENT_SECRET_HASH
                .get()
                .map_or(FALLBACK_DUMMY_CLIENT_SECRET_HASH, |s| s.as_str())
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to prepare dummy client secret hash; falling back to the constant PHC string"
            );
            FALLBACK_DUMMY_CLIENT_SECRET_HASH
        }
    }
}

/// 在服务开始接受请求前预热 dummy 哈希，避免首个失败认证多执行一次 Argon2 哈希生成。
pub(crate) fn prepare_dummy_client_secret_hash() {
    let _ = dummy_client_secret_hash();
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
/// 先比较策略门，再选择真实或 dummy hash；无论门、secret 或 client 是否存在，
/// 都在 blocking 线程执行一次 Argon2。公开客户端仍要求请求和数据库都没有 secret。
/// 最终判定使用非短路 `&`，防止失败分支跳过已完成的计算。
pub async fn verify_client_credentials_constant_time(
    requested_method: ClientAuthMethod,
    client_secret: Option<&str>,
    stored: Option<&StoredClientCredentials>,
) -> bool {
    let client_secret = client_secret.map(str::to_owned);
    let stored = stored.map(|stored| StoredClientCredentials {
        client_secret_hash: stored.client_secret_hash.clone(),
        auth_method: stored.auth_method.clone(),
        status: stored.status.clone(),
    });
    match tokio::task::spawn_blocking(move || {
        verify_client_credentials_constant_time_blocking(
            requested_method,
            client_secret.as_deref(),
            stored.as_ref(),
        )
    })
    .await
    {
        Ok(valid) => valid,
        Err(error) => {
            tracing::error!(error = %error, "constant-time client credential task failed to join");
            false
        }
    }
}

#[allow(clippy::needless_bitwise_bool, clippy::nonminimal_bool)]
fn verify_client_credentials_constant_time_blocking(
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
        Some(hash) if PasswordHash::new(hash).is_ok() => hash,
        _ => dummy_client_secret_hash(),
    };

    // 选取探针：请求携带 secret 则用请求值；否则用探针常量（不能通过任何真实 hash 的验证）。
    let secret_for_verify: &str = client_secret.unwrap_or(DUMMY_SECRET_PROBE);

    // 无条件执行一次 Argon2 verify —— 这是本函数的核心：
    // 无论 client 是否存在、status / method 是否合法，都付出相同的 Argon2 计算代价，
    // 使攻击者无法通过响应时间区分「client_id 不存在」与「secret 错误」。
    let argon2_ok = verify_client_secret_blocking(secret_for_verify, hash_for_verify);

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
        let hash1 = super::dummy_client_secret_hash();
        let hash2 = super::dummy_client_secret_hash();
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

    #[tokio::test]
    async fn constant_time_verify_rejects_gate_failures() {
        // client 不存在
        assert!(
            !verify_client_credentials_constant_time(ClientAuthMethod::Basic, Some("s"), None)
                .await
        );
        // status disabled
        assert!(
            !verify_client_credentials_constant_time(
                ClientAuthMethod::Basic,
                Some("s"),
                Some(&stored("client_secret_basic", "disabled", Some("h")))
            )
            .await
        );
        // method 不匹配
        assert!(
            !verify_client_credentials_constant_time(
                ClientAuthMethod::Post,
                Some("s"),
                Some(&stored("client_secret_basic", "active", Some("h")))
            )
            .await
        );
    }

    #[tokio::test]
    async fn constant_time_verify_accepts_public_client_without_secret() {
        assert!(
            verify_client_credentials_constant_time(
                ClientAuthMethod::None,
                None,
                Some(&stored("none", "active", None))
            )
            .await
        );
    }

    #[tokio::test]
    async fn constant_time_verify_rejects_public_client_edge_cases() {
        // 请求携带了不该有的 secret
        assert!(
            !verify_client_credentials_constant_time(
                ClientAuthMethod::None,
                Some("unexpected"),
                Some(&stored("none", "active", None))
            )
            .await
        );
        // 数据库遗留了 hash（配置错误），fail closed
        assert!(
            !verify_client_credentials_constant_time(
                ClientAuthMethod::None,
                None,
                Some(&stored("none", "active", Some("$argon2...")))
            )
            .await
        );
    }

    #[tokio::test]
    async fn constant_time_verify_accepts_correct_confidential_secret() {
        // 生成真实 Argon2 哈希（昂贵操作，覆盖完整路径所必需）
        let (plaintext, hash) = generate_client_secret().expect("generate secret");
        let s = stored("client_secret_basic", "active", Some(&hash));
        assert!(
            verify_client_credentials_constant_time(
                ClientAuthMethod::Basic,
                Some(&plaintext),
                Some(&s)
            )
            .await
        );
    }

    #[tokio::test]
    async fn constant_time_verify_rejects_wrong_or_missing_secret() {
        let (_, hash) = generate_client_secret().expect("generate secret");
        let s = stored("client_secret_basic", "active", Some(&hash));
        // 错误 secret
        assert!(
            !verify_client_credentials_constant_time(
                ClientAuthMethod::Basic,
                Some("cxs_wrong"),
                Some(&s)
            )
            .await
        );
        // 缺少 secret
        assert!(
            !verify_client_credentials_constant_time(ClientAuthMethod::Basic, None, Some(&s)).await
        );
    }
}
