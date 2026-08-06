use std::time::{SystemTime, UNIX_EPOCH};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use totp_rs::{Algorithm, Secret, TOTP};

use super::domain::validate_totp_code;

const TOTP_DIGITS: usize = 6;
pub(crate) const TOTP_SKEW: u8 = 1;
pub(crate) const TOTP_STEP_SECONDS: u64 = 30;

/// TOTP 注册信息，持有预构建的 TOTP 实例以消除 `code_at` 的失败路径。
///
/// 安全注意：Debug 实现会隐藏所有敏感字段（种子、Base32 表示和 TOTP 实例），
/// 防止密钥材料泄漏到日志。
#[derive(Clone)]
pub struct TotpEnrollment {
    /// 预构建的 TOTP 实例，缓存避免每次 `code_at` 调用都重新构造。
    /// 码生成只依赖 algorithm、digits、step 和 secret，不依赖 issuer/account_name。
    totp: TOTP,
    /// Base32 编码的种子，供用户在注册时手动输入使用。
    secret_base32: String,
    /// otpauth:// URI，供二维码生成使用。
    otpauth_url: String,
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("totp", &"<redacted>")
            .field("secret_base32", &"<redacted>")
            .field("otpauth_url", &"<redacted>")
            .finish()
    }
}

impl TotpEnrollment {
    pub fn new(account_name: &str, issuer: &str) -> Result<Self, totp_rs::TotpUrlError> {
        let secret = Secret::generate_secret().to_bytes().map_err(|_| {
            totp_rs::TotpUrlError::Secret("could not generate TOTP secret".to_owned())
        })?;
        Ok(Self::from_built_totp(build_totp(
            secret,
            account_name,
            issuer,
        )?))
    }

    pub fn from_secret(secret: Vec<u8>, account_name: &str, issuer: &str) -> Option<Self> {
        Some(Self::from_built_totp(
            build_totp(secret, account_name, issuer).ok()?,
        ))
    }

    /// 唯一的构造入口：TOTP 实例只在这里被缓存。
    /// 构造已经成功，所以这里没有失败路径，`code_at` 也就不再需要 `expect`。
    fn from_built_totp(totp: TOTP) -> Self {
        Self {
            secret_base32: totp.get_secret_base32(),
            otpauth_url: totp.get_url(),
            totp,
        }
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.totp.secret
    }

    pub fn secret_base32(&self) -> &str {
        &self.secret_base32
    }

    pub fn otpauth_url(&self) -> &str {
        &self.otpauth_url
    }

    /// 生成指定时间戳对应的码。使用构造期缓存的 TOTP 实例，
    /// 因此既没有 `expect` 的 panic 风险，也不需要每次克隆种子。
    ///
    /// 码只由 algorithm、digits、step 和 secret 决定，issuer 与 account_name
    /// 仅影响 otpauth URI，所以缓存带真实标签的实例与旧实现产生完全相同的码。
    pub fn code_at(&self, timestamp: u64) -> String {
        self.totp.generate(timestamp)
    }
}

pub fn verify_totp_code_at(secret: &[u8], code: &str, timestamp: u64) -> bool {
    verify_totp_code_at_timestep(secret, code, timestamp).is_some()
}

pub fn verify_totp_code_at_timestep(secret: &[u8], code: &str, timestamp: u64) -> Option<u64> {
    // 快速格式验证（长度和数字校验不会泄漏密钥信息）。
    if validate_totp_code(code).is_err() {
        return None;
    }
    let totp = build_totp(secret.to_vec(), "", "").ok()?;
    let current_step = timestamp / TOTP_STEP_SECONDS;

    // 使用常量时间比较防止时序攻击。
    //
    // 理由：TOTP 码源自从种子推导的秘密值，属于凭据比较。虽然码空间只有
    // 6 位十进制、30 秒轮换、有限流和重放保护，但常量时间比较的成本极低，
    // 没有理由保留可观测的时序差异。
    //
    // 实现注意：
    // - `subtle` 的切片 `ct_eq` 在长度不等时会短路，但 TOTP 码固定 6 位，
    //   长度本身不是秘密，这个短路可以接受。
    // - 循环体必须完整执行，不能提前 return，以消除"匹配位置"泄漏的时序信息。
    // - 使用 `Choice` 和 `ConditionallySelectable` 在常量时间内累积结果。
    let mut matched = Choice::from(0u8);
    let mut matched_step: u64 = 0;

    for offset in -(TOTP_SKEW as i64)..=(TOTP_SKEW as i64) {
        let step = current_step as i64 + offset;
        // step >= 0 属于输入合法性检查（时间戳过小会算出负步数），不是秘密比较，
        // 用普通布尔判断即可；关键是无论它是否成立，生成与比较都要照样执行完。
        let step_valid = Choice::from(u8::from(step >= 0));
        let candidate_step = step.max(0) as u64;
        let expected = totp.generate(candidate_step * TOTP_STEP_SECONDS);
        let hit = expected.as_bytes().ct_eq(code.as_bytes()) & step_valid;

        // 只在首次命中时记录 timestep，保持原实现"最早匹配的步优先"的语义。
        let first_hit = hit & !matched;
        matched_step = u64::conditional_select(&matched_step, &candidate_step, first_hit);
        matched |= hit;
    }

    bool::from(matched).then_some(matched_step)
}

pub fn verify_totp_code_current(secret: &[u8], code: &str) -> bool {
    verify_totp_code_current_timestep(secret, code).is_some()
}

pub fn verify_totp_code_current_timestep(secret: &[u8], code: &str) -> Option<u64> {
    let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return None;
    };
    verify_totp_code_at_timestep(secret, code, timestamp.as_secs())
}

fn build_totp(
    secret: Vec<u8>,
    account_name: &str,
    issuer: &str,
) -> Result<TOTP, totp_rs::TotpUrlError> {
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECONDS,
        secret,
        Some(issuer.to_owned()),
        account_name.to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的 SHA1 测试种子。
    const RFC_SECRET: &[u8] = b"12345678901234567890";
    /// 步对齐的时间戳：1_700_000_010 / 30 == 56_666_667，便于推算窗口边界。
    const ALIGNED_NOW: u64 = 1_700_000_010;

    fn rfc_enrollment() -> TotpEnrollment {
        TotpEnrollment::from_secret(RFC_SECRET.to_vec(), "user@example.com", "Chenxing")
            .expect("RFC test seed is valid")
    }

    #[test]
    fn new_exposes_uri_base32_and_seed() {
        let enrollment = TotpEnrollment::new("user@example.com", "Chenxing").unwrap();
        assert!(enrollment.otpauth_url().starts_with("otpauth://totp/"));
        assert!(enrollment.otpauth_url().contains("issuer=Chenxing"));
        assert_eq!(enrollment.secret_base32().len() % 8, 0);
        assert!(!enrollment.secret_bytes().is_empty());
    }

    #[test]
    fn from_secret_round_trips_seed_and_base32() {
        let enrollment = rfc_enrollment();
        assert_eq!(enrollment.secret_bytes(), RFC_SECRET);
        assert_eq!(
            enrollment.secret_base32(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    /// 缓存 TOTP 实例后 `code_at` 必须仍然产出 RFC 规定的码：
    /// 证明"构造期缓存"没有改变码生成语义（issuer/account_name 不参与 HMAC）。
    #[test]
    fn code_at_matches_rfc6238_vectors() {
        let enrollment = rfc_enrollment();
        assert_eq!(enrollment.code_at(59), "287082");
        assert_eq!(enrollment.code_at(1_111_111_109), "081804");
        assert_eq!(enrollment.code_at(1_111_111_111), "050471");
        assert_eq!(enrollment.code_at(1_234_567_890), "005924");
        assert_eq!(enrollment.code_at(2_000_000_000), "279037");
    }

    #[test]
    fn code_at_round_trips_through_verification_for_fresh_enrollment() {
        let enrollment = TotpEnrollment::new("user@example.com", "Chenxing").unwrap();
        let code = enrollment.code_at(ALIGNED_NOW);
        assert_eq!(code.len(), TOTP_DIGITS);
        assert!(verify_totp_code_at(
            enrollment.secret_bytes(),
            &code,
            ALIGNED_NOW
        ));
    }

    #[test]
    fn verify_rejects_wrong_code() {
        // 这两个码不在 ALIGNED_NOW 的 ±1 步窗口内（已用独立 HMAC 实现核对）。
        assert!(!verify_totp_code_at(RFC_SECRET, "000000", ALIGNED_NOW));
        assert!(!verify_totp_code_at(RFC_SECRET, "999999", ALIGNED_NOW));
    }

    #[test]
    fn verify_rejects_malformed_codes() {
        for bad in ["12345", "1234567", "12345a", "", "  1234"] {
            assert!(
                !verify_totp_code_at(RFC_SECRET, bad, ALIGNED_NOW),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn verify_accepts_every_step_inside_the_skew_window() {
        let enrollment = rfc_enrollment();
        for offset in [-30_i64, 0, 30] {
            let ts = ALIGNED_NOW.wrapping_add(offset as u64);
            let code = enrollment.code_at(ts);
            assert!(
                verify_totp_code_at(enrollment.secret_bytes(), &code, ALIGNED_NOW),
                "offset {offset} should be inside the skew window"
            );
        }
    }

    #[test]
    fn verify_rejects_steps_outside_the_skew_window() {
        let enrollment = rfc_enrollment();
        for offset in [-90_i64, -60, 60, 90] {
            let ts = ALIGNED_NOW.wrapping_add(offset as u64);
            let code = enrollment.code_at(ts);
            assert!(
                !verify_totp_code_at(enrollment.secret_bytes(), &code, ALIGNED_NOW),
                "offset {offset} should be outside the skew window"
            );
        }
    }

    #[test]
    fn verify_returns_the_accepted_timestep() {
        let enrollment = rfc_enrollment();
        let secret = enrollment.secret_bytes();
        for offset in [-30_i64, 0, 30] {
            let ts = ALIGNED_NOW.wrapping_add(offset as u64);
            assert_eq!(
                verify_totp_code_at_timestep(secret, &enrollment.code_at(ts), ALIGNED_NOW),
                Some(ts / TOTP_STEP_SECONDS),
                "offset {offset} should report its own timestep"
            );
        }
        assert_eq!(
            verify_totp_code_at_timestep(secret, "000000", ALIGNED_NOW),
            None
        );
    }

    /// 常量时间循环用 `step.max(0)` 代替提前 return，所以必须确认
    /// 小时间戳（负 offset 会算出负步）既不 panic 也不接受非法步。
    #[test]
    fn small_timestamps_do_not_underflow_the_step_window() {
        let enrollment = rfc_enrollment();
        let secret = enrollment.secret_bytes();
        // timestamp = 10 → current_step = 0，offset -1 得到的 step 为负，必须被屏蔽。
        assert_eq!(verify_totp_code_at_timestep(secret, "755224", 10), Some(0));
        assert_eq!(verify_totp_code_at_timestep(secret, "287082", 10), Some(1));
        assert_eq!(verify_totp_code_at_timestep(secret, "000000", 10), None);
    }

    #[test]
    fn debug_output_redacts_secret_material() {
        let enrollment = rfc_enrollment();
        let rendered = format!("{enrollment:?}");
        assert!(rendered.contains("TotpEnrollment"));
        assert!(!rendered.contains(enrollment.secret_base32()));
        assert!(!rendered.contains("12345678901234567890"));
        assert!(!rendered.contains(enrollment.otpauth_url()));
    }
}
