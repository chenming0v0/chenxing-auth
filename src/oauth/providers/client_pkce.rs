//! 本系统作为 OAuth 客户端访问外部 IdP 时的 PKCE 支持。
//!
//! RFC 9700 §2.1.1 要求所有授权码流程都使用 PKCE，不区分公开客户端和机密客户端。
//! 本模块负责生成 `code_verifier` 并派生 S256 `code_challenge`。
//!
//! 与 `crate::oauth::pkce` 的分工：那个模块是**服务端**视角（校验外部客户端提交的
//! challenge / verifier）；本模块是**客户端**视角（生成自己的 verifier 并派生
//! challenge）。两者共用同一套 RFC 7636 定义的编码规则：
//! `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`。

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// verifier 熵源字节数。32 字节经 base64url 无填充编码后恰好 43 字符，
/// 正好命中 RFC 7636 §4.1 允许的最短长度，且字母表天然落在
/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` 内。
const VERIFIER_ENTROPY_BYTES: usize = 32;

/// 生成符合 RFC 7636 §4.1 的 `code_verifier`。
///
/// 返回值是一次性凭据，禁止写入日志、审计详情或错误响应。
pub fn generate_code_verifier() -> String {
    let mut bytes = [0_u8; VERIFIER_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 由 `code_verifier` 派生 S256 `code_challenge`。
///
/// RFC 7636 §4.2：`code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`。
pub fn s256_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 §4.1 规定 verifier 长度 43-128 字符；43 是 32 字节熵的编码长度。
    #[test]
    fn generated_verifier_has_rfc_7636_length() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 43);
        assert!((43..=128).contains(&verifier.len()));
    }

    /// verifier 必须只含 RFC 7636 的 unreserved 字符集，否则外部 IdP 可能拒绝。
    #[test]
    fn generated_verifier_uses_rfc_7636_alphabet() {
        for _ in 0..64 {
            let verifier = generate_code_verifier();
            assert!(
                verifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
                "verifier 含非法字符: {verifier}"
            );
        }
    }

    #[test]
    fn generated_verifiers_are_unique() {
        let first = generate_code_verifier();
        let second = generate_code_verifier();
        assert_ne!(first, second, "verifier 必须每次随机生成");
    }

    /// RFC 7636 附录 B 的官方测试向量。
    #[test]
    fn s256_matches_rfc_7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_code_challenge(verifier), challenge);
    }

    /// 生成的 verifier 派生出的 challenge 必须能通过服务端校验逻辑，
    /// 证明客户端侧与服务端侧对 S256 的理解一致。
    #[test]
    fn generated_pair_passes_server_side_verification() {
        let verifier = generate_code_verifier();
        let challenge = s256_code_challenge(&verifier);
        assert_eq!(challenge.len(), 43);
        crate::oauth::pkce::validate_s256_challenge(&challenge)
            .expect("派生的 challenge 应通过服务端格式校验");
        crate::oauth::pkce::verify_s256(&verifier, &challenge)
            .expect("派生的 challenge 应与 verifier 匹配");
    }
}
