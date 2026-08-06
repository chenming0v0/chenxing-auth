//! 口令哈希与校验边界（Issue #122 / #124）。
//!
//! Argon2 的默认参数是 19 MiB 内存、2 次迭代，单次哈希约 50 ms 且 CPU 密集。
//! 这类调用不能留在 async 函数体里直接执行：Tokio worker 在 `.await` 之前无法
//! 被抢占，一次登录就会占住整个线程 50 ms。并发登录量稍高时，worker 全部卡在
//! Argon2 上，同一运行时里的所有任务（含健康检查和已建立连接的读写）一起停摆。
//!
//! 因此本模块只暴露 async 接口，内部统一经 `tokio::task::spawn_blocking` 把计算
//! 搬到阻塞线程池。口令按值 move 进闭包（`String` 而非 `&str`）：闭包要求
//! `'static + Send`，借用无法满足，而调用方本来就持有 owned 明文并在调用后丢弃。

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use std::sync::OnceLock;

const DUMMY_PASSWORD: &str = "chenxing-auth-dummy-password";
static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

/// 哑哈希的编译期兜底 PHC 串（Issue #124）。
///
/// 用途只有一个：当运行期生成哑哈希失败（OsRng 不可用等）时，仍然让
/// `verify_login_password` 走完一次真实的 Argon2 计算。
///
/// 旧实现在失败时把 `String::new()` 写进 `OnceLock` 并**永久缓存**。空串无法被
/// `PasswordHash::new` 解析，于是"用户不存在"分支直接跳过整个 Argon2，比"口令
/// 错误"分支快 50 ms 返回。这个差异足以让攻击者批量枚举哪些用户名/邮箱已注册，
/// 而且一旦缓存就再也不会自愈。
///
/// 参数与 `Argon2::default()` 一致（argon2id、v=19、m=19456、t=2、p=1），
/// 计算代价与真实校验相同。verify 时参数从 PHC 串本身读取，所以这里的 m/t/p
/// 决定实际开销，必须与默认值同步。
///
/// salt 为 16 字节、digest 为 32 字节，都是全零：格式合法可解析，但没有任何口令
/// 能哈希出全零摘要，因此校验恒定失败——这正是计时填充需要的语义。
///
/// **格式必须合法**：若这个串无法被 `PasswordHash::new` 解析，兜底失效、防御归零。
/// `fallback_dummy_hash_is_a_valid_phc_string` 用编译期常量在测试中锁死这一点。
const FALLBACK_DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 口令最大长度（字符数，Issue #122）。
///
/// Argon2 的成本随口令长度增长。没有上界时，一个请求可以提交数 MB 的口令，
/// 把单次哈希从 50 ms 放大到数秒，直接变成放大攻击；限流按请求数计，拦不住
/// 单请求的计算量。128 字符对真实口令和 passphrase 都绰绰有余。
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// 同步哈希实现，只允许在阻塞线程里调用。
fn hash_password_blocking(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

/// 同步校验实现，只允许在阻塞线程里调用。
fn verify_password_blocking(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

/// 计算口令哈希。
///
/// 口令按值接收：调用方持有 owned 明文，move 进阻塞闭包既满足 `'static`，
/// 也避免为跨线程再复制一份明文。
pub async fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    // spawn_blocking 的 JoinError 只在闭包 panic 或运行时关闭时出现。Argon2 哈希
    // 不 panic，这里把 JoinError 归一为 password_hash::Error::Algorithm 而不是
    // unwrap：启动关闭竞争期的请求应当收到失败响应，不该让整个 worker 崩掉。
    match tokio::task::spawn_blocking(move || hash_password_blocking(&password)).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "password hashing task failed to join");
            Err(argon2::password_hash::Error::Algorithm)
        }
    }
}

/// 校验口令与哈希是否匹配。
///
/// 任何内部失败（解析失败、任务 join 失败）都返回 `false`：校验是安全判定，
/// 出错时必须 fail-closed，不能把不确定状态当成通过。
pub async fn verify_password(password: String, encoded_hash: String) -> bool {
    match tokio::task::spawn_blocking(move || verify_password_blocking(&password, &encoded_hash))
        .await
    {
        Ok(valid) => valid,
        Err(error) => {
            tracing::error!(error = %error, "password verification task failed to join");
            false
        }
    }
}

/// 进程启动时预热哑哈希。
///
/// 同步执行一次 Argon2（约 50 ms），发生在监听端口之前、任何请求到达之前，
/// 因此不占用服务期的 worker。目的是把首个登录请求的哑哈希生成成本前移，
/// 让"用户不存在"路径从第一次请求起就与"口令错误"路径等时。
pub fn prepare_dummy_password_hash() {
    let _ = dummy_password_hash();
}

/// 登录口令校验，附带用户不存在时的计时填充。
///
/// `encoded_hash` 为 `None` 表示标识符没有匹配到用户。此时仍然对哑哈希执行一次
/// 完整的 Argon2 校验，使两条路径耗时一致，不泄露账号是否存在。
pub async fn verify_login_password(password: String, encoded_hash: Option<String>) -> bool {
    match encoded_hash {
        Some(hash) => verify_password(password, hash).await,
        None => {
            // 哑哈希的读取和 Argon2 计算一并放进阻塞线程：首次调用可能需要现场
            // 生成哈希（本身就是一次 Argon2），不能留在 async 上下文里执行。
            let joined = tokio::task::spawn_blocking(move || {
                verify_password_blocking(&password, dummy_password_hash())
            })
            .await;
            if let Err(error) = joined {
                tracing::error!(error = %error, "dummy password verification task failed to join");
            }
            false
        }
    }
}

/// 返回哑哈希，失败时退回编译期常量且**不写入缓存**。
///
/// 与旧实现的三个差异（Issue #124）：
/// 1. 失败不进 `OnceLock`，下次调用重试，暂时性故障可自愈；
/// 2. 失败时返回合法 PHC 常量而不是空串，Argon2 仍然执行，计时防御不失效；
/// 3. 失败记 `tracing::error!`，运维可见。
fn dummy_password_hash() -> &'static str {
    if let Some(hash) = DUMMY_PASSWORD_HASH.get() {
        return hash.as_str();
    }
    match hash_password_blocking(DUMMY_PASSWORD) {
        Ok(hash) => {
            // 并发下 set 可能失败，说明另一线程已写入，用已存在的值即可。
            let _ = DUMMY_PASSWORD_HASH.set(hash);
            DUMMY_PASSWORD_HASH
                .get()
                .map_or(FALLBACK_DUMMY_PASSWORD_HASH, |hash| hash.as_str())
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "failed to prepare dummy password hash; falling back to the constant PHC string"
            );
            FALLBACK_DUMMY_PASSWORD_HASH
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DUMMY_PASSWORD, FALLBACK_DUMMY_PASSWORD_HASH, MAX_PASSWORD_LENGTH, dummy_password_hash,
        hash_password, verify_login_password, verify_password, verify_password_blocking,
    };
    use argon2::password_hash::PasswordHash;

    #[tokio::test]
    async fn dummy_password_path_uses_a_reusable_argon2_hash() {
        let hash = dummy_password_hash();
        assert!(hash.starts_with("$argon2"));
        assert!(!verify_login_password(DUMMY_PASSWORD.to_owned(), None).await);
        assert!(!verify_login_password("wrong dummy password".to_owned(), None).await);
    }

    /// Issue #124 的核心回归：兜底常量必须是合法 PHC 串。
    ///
    /// 若它无法解析，`verify_password_blocking` 会在 `PasswordHash::new` 处提前
    /// 返回，跳过 Argon2，"用户不存在"重新变成可计时区分的快路径。
    #[test]
    fn fallback_dummy_hash_is_a_valid_phc_string() {
        let parsed = PasswordHash::new(FALLBACK_DUMMY_PASSWORD_HASH)
            .expect("fallback dummy hash must be parseable, otherwise Argon2 is skipped");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert!(parsed.salt.is_some(), "fallback hash must carry a salt");
        assert!(parsed.hash.is_some(), "fallback hash must carry a digest");
    }

    /// 兜底常量的参数必须与 `Argon2::default()` 一致，否则计时填充的代价对不上。
    #[test]
    fn fallback_dummy_hash_matches_default_argon2_cost() {
        let parsed = PasswordHash::new(FALLBACK_DUMMY_PASSWORD_HASH).expect("valid PHC string");
        let params: std::collections::HashMap<_, _> = parsed
            .params
            .iter()
            .map(|(key, value)| (key.as_str().to_owned(), value.to_string()))
            .collect();
        assert_eq!(params.get("m").map(String::as_str), Some("19456"));
        assert_eq!(params.get("t").map(String::as_str), Some("2"));
        assert_eq!(params.get("p").map(String::as_str), Some("1"));
        assert_eq!(parsed.version, Some(19));
    }

    /// 兜底常量可解析且校验恒失败：既跑完 Argon2，又不会放行任何口令。
    #[test]
    fn fallback_dummy_hash_never_accepts_a_password() {
        assert!(!verify_password_blocking("", FALLBACK_DUMMY_PASSWORD_HASH));
        assert!(!verify_password_blocking(
            DUMMY_PASSWORD,
            FALLBACK_DUMMY_PASSWORD_HASH
        ));
    }

    #[tokio::test]
    async fn async_hash_and_verify_round_trip() {
        let password = "correct horse battery staple".to_owned();
        let hash = hash_password(password.clone())
            .await
            .expect("password hash");
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(password, hash.clone()).await);
        assert!(!verify_password("wrong password".to_owned(), hash).await);
    }

    #[tokio::test]
    async fn verify_password_rejects_malformed_hashes() {
        // fail-closed：哈希损坏不能被当成校验通过。
        assert!(!verify_password("anything".to_owned(), String::new()).await);
        assert!(!verify_password("anything".to_owned(), "not-a-phc-string".to_owned()).await);
    }

    #[tokio::test]
    async fn login_verification_accepts_the_stored_hash() {
        let password = "correct horse battery staple".to_owned();
        let hash = hash_password(password.clone())
            .await
            .expect("password hash");
        assert!(verify_login_password(password, Some(hash.clone())).await);
        assert!(!verify_login_password("wrong password".to_owned(), Some(hash)).await);
    }

    #[test]
    fn max_password_length_is_a_sane_upper_bound() {
        // 上界既要挡住放大攻击，也不能挡住真实的长 passphrase。
        assert_eq!(MAX_PASSWORD_LENGTH, 128);
    }
}
