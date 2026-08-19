use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub mod auth_handlers;
pub mod authorization;
pub mod bootstrap_guard;
mod client_errors;
pub mod domain;
pub mod factor_handlers;
pub mod handlers;
pub mod invitation_code_handlers;
pub mod issuer_settings_handlers;
pub mod key_handlers;
pub mod management_handlers;
pub mod passkey_recovery;
pub mod plan_handlers;
pub mod provider_handlers;
pub mod provider_web_handlers;
pub mod registration_settings_handlers;
pub mod settings_handlers;
pub mod ui_handlers;
pub mod user_creation;
pub mod web_handlers;

/// ADMIN_TOKEN 验证器。
///
/// 通过对双方令牌分别计算 HMAC-SHA256 后比较定长摘要，消除令牌长度差异
/// 带来的时序侧信道攻击面（修复 #71）。
/// `mac_key` 在进程启动时随机生成，不对外暴露，不写入日志。
#[derive(Clone)]
pub struct AdminAuthenticator {
    token: String,
    /// 仅用于 is_valid 内部 HMAC 比较的随机 key，不包含任何业务秘密
    mac_key: [u8; 32],
}

impl AdminAuthenticator {
    pub fn new(token: String) -> Self {
        let mut mac_key = [0u8; 32];
        // 使用密码学安全随机源生成内部 MAC key，确保每次进程启动都不同
        OsRng.fill_bytes(&mut mac_key);
        Self { token, mac_key }
    }

    /// 将候选令牌和配置令牌分别通过同一内部 key 的 HMAC-SHA256 映射到定长摘要，
    /// 再执行常量时间比较。无论候选令牌长短，外部观察者无法通过响应时间推断
    /// 配置令牌的长度。
    pub fn is_valid(&self, candidate: &str) -> bool {
        // ADMIN_TOKEN 为空时，系统 Bearer Token 通道整体关闭：没有任何候选值能通过。
        //
        // 这只是两条管理通道中的一条（Issue #305）。「空 Token = 整个管理面关闭」
        // 由 `api::extract::AdminCaller::resolve` 的 fail-closed 检查保证（Issue #348）：
        // ADMIN_TOKEN 为空时它会拒绝包括浏览器 Session 在内的全部管理请求。
        // 不存在 Owner 时公开的首个 Owner 初始化接口不经过该提取器，例外语义不变。
        if self.token.is_empty() {
            return false;
        }

        let hmac_of = |input: &str| {
            // HMAC 接受任意长度的 key，此处 32 字节 key 不会触发 InvalidLength 错误
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.mac_key)
                .expect("HMAC 接受任意长度的 key，32 字节 key 不会失败");
            mac.update(input.as_bytes());
            mac.finalize().into_bytes()
        };

        // 两个 HMAC-SHA256 输出长度固定为 32 字节，在 &[u8] 上执行常量时间比较
        let a = hmac_of(&self.token);
        let b = hmac_of(candidate);
        a.as_slice().ct_eq(b.as_slice()).into()
    }

    pub fn is_authorization_header_valid(&self, value: &str) -> bool {
        let Some((scheme, token)) = value.split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("Bearer") && self.is_valid(token)
    }
}
