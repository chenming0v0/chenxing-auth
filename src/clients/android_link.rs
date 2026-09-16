//! Android App Links 声明（`/.well-known/assetlinks.json`）。
//!
//! 辰星域名可以充当移动端 OAuth 客户端的 HTTPS 回调落地链接（`/app/<id>/oauth/callback`），
//! Android 只有在链接域名下取到列有 App 包名和签名指纹的 Digital Asset Links 声明后，
//! 才会把回调链接交给 App 而不是浏览器。
//!
//! 声明是 Client 的所属属性，不是管理员专属开关。所有者走
//! `/api/v1/auth/oauth-clients/{id}/app-link`，管理面 `/api/v1/admin/app-links`
//! 是全站覆盖。都不是 Client 注册/更新入参。公开端点只发布已登记声明；同包名
//! 多 Client 的指纹合并到同一 statement。
//!
//! 指纹是公钥派生，不是秘密，也不需要保密；格式统一为大写冒号分隔，便于确定性发布。

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 单个 Client 最多声明的签名指纹数量：够覆盖调试/发布/上传密钥轮换，又不至于失控。
pub const MAX_ANDROID_FINGERPRINTS: usize = 8;

const MAX_ANDROID_PACKAGE_NAME_LENGTH: usize = 255;
const SHA256_FINGERPRINT_HEX_LENGTH: usize = 64;

/// 已校验的 App Links 声明。`sha256_cert_fingerprints` 统一为大写冒号分隔形式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidAssetLink {
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

/// API 入参形态，字段名与 Digital Asset Links 规范一致。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AndroidAssetLinkInput {
    pub package_name: String,
    #[serde(default)]
    pub sha256_cert_fingerprints: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AndroidAssetLinkError {
    #[error("Android package name is invalid")]
    InvalidPackageName,
    #[error("Android SHA-256 certificate fingerprint is invalid")]
    InvalidFingerprint,
}

pub fn validate_android_asset_link(
    input: Option<AndroidAssetLinkInput>,
) -> Result<Option<AndroidAssetLink>, AndroidAssetLinkError> {
    let Some(input) = input else {
        return Ok(None);
    };
    let package_name = input.package_name.trim().to_owned();
    if !is_android_package_name(&package_name) {
        return Err(AndroidAssetLinkError::InvalidPackageName);
    }
    if input.sha256_cert_fingerprints.is_empty()
        || input.sha256_cert_fingerprints.len() > MAX_ANDROID_FINGERPRINTS
    {
        return Err(AndroidAssetLinkError::InvalidFingerprint);
    }

    let mut fingerprints: Vec<String> = Vec::with_capacity(input.sha256_cert_fingerprints.len());
    for raw in input.sha256_cert_fingerprints {
        let fingerprint =
            normalize_fingerprint(&raw).ok_or(AndroidAssetLinkError::InvalidFingerprint)?;
        if !fingerprints.contains(&fingerprint) {
            fingerprints.push(fingerprint);
        }
    }
    if fingerprints.is_empty() {
        return Err(AndroidAssetLinkError::InvalidFingerprint);
    }

    Ok(Some(AndroidAssetLink {
        package_name,
        sha256_cert_fingerprints: fingerprints,
    }))
}

/// Android 包名：至少两段点分隔的 Java 标识符（ASCII 字母开头，后接字母/数字/下划线）。
fn is_android_package_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ANDROID_PACKAGE_NAME_LENGTH {
        return false;
    }
    let mut segments = 0;
    for segment in value.split('.') {
        let mut chars = segment.chars();
        if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
            return false;
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

/// 接受 `AA:BB:…` 与 `aabb…` 两种写法，输出统一大写冒号分隔。
fn normalize_fingerprint(value: &str) -> Option<String> {
    let hex: Vec<u8> = value
        .bytes()
        .filter(|byte| *byte != b':')
        .map(|byte| byte.to_ascii_uppercase())
        .collect();
    if hex.len() != SHA256_FINGERPRINT_HEX_LENGTH || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(
        hex.chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("ascii hex digits"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
    const FP_B: &str = "B6:DA:01:48:0E:EF:D5:FB:F2:CD:37:71:B8:D1:02:1E:C7:91:30:4B:DD:6C:4B:F4:1D:3F:AA:BA:D4:8E:E5:E1";

    fn input(package_name: &str, fingerprints: &[&str]) -> Option<AndroidAssetLinkInput> {
        Some(AndroidAssetLinkInput {
            package_name: package_name.to_owned(),
            sha256_cert_fingerprints: fingerprints.iter().map(|f| (*f).to_owned()).collect(),
        })
    }

    #[test]
    fn absent_input_stays_absent() {
        assert_eq!(validate_android_asset_link(None), Ok(None));
    }

    #[test]
    fn colon_and_plain_formats_normalize_to_same_form() {
        let from_colons = validate_android_asset_link(input("com.chengming.termux", &[FP_A]))
            .expect("valid")
            .expect("declared");
        let from_plain = validate_android_asset_link(input(
            "com.chengming.termux",
            &[&FP_A.replace(':', "").to_lowercase()],
        ))
        .expect("valid")
        .expect("declared");
        assert_eq!(from_colons, from_plain);
        assert_eq!(from_colons.sha256_cert_fingerprints, vec![FP_A.to_owned()]);
        assert_eq!(from_colons.package_name, "com.chengming.termux");
    }

    #[test]
    fn multiple_fingerprints_collapse_duplicates() {
        let link = validate_android_asset_link(input(
            "com.chengming.termux",
            &[FP_A, FP_B, FP_A, &FP_B.to_lowercase()],
        ))
        .expect("valid")
        .expect("declared");
        assert_eq!(
            link.sha256_cert_fingerprints.len(),
            2,
            "duplicates collapse"
        );
        assert!(link.sha256_cert_fingerprints.contains(&FP_A.to_owned()));
        assert!(link.sha256_cert_fingerprints.contains(&FP_B.to_owned()));
    }

    #[test]
    fn package_name_is_trimmed_and_must_be_namespaced() {
        assert_eq!(
            validate_android_asset_link(input("  com.chengming.termux  ", &[FP_A]))
                .expect("valid")
                .expect("declared")
                .package_name,
            "com.chengming.termux"
        );
        for package_name in [
            "termux",
            "",
            "com.1bad.pkg",
            "com.bad-pkg.app",
            "com..x",
            ".a.b",
        ] {
            assert_eq!(
                validate_android_asset_link(input(package_name, &[FP_A])),
                Err(AndroidAssetLinkError::InvalidPackageName),
                "{package_name}"
            );
        }
    }

    #[test]
    fn malformed_or_excessive_fingerprints_are_rejected() {
        assert_eq!(
            validate_android_asset_link(input("com.a.b", &[""])),
            Err(AndroidAssetLinkError::InvalidFingerprint)
        );
        assert_eq!(
            validate_android_asset_link(input("com.a.b", &["14:6D:E9"])),
            Err(AndroidAssetLinkError::InvalidFingerprint)
        );
        assert_eq!(
            validate_android_asset_link(input("com.a.b", &[&FP_A.replace('4', "G")])),
            Err(AndroidAssetLinkError::InvalidFingerprint)
        );
        let too_many: Vec<&str> = std::iter::repeat_n(FP_A, MAX_ANDROID_FINGERPRINTS + 1).collect();
        assert_eq!(
            validate_android_asset_link(input("com.a.b", &too_many)),
            Err(AndroidAssetLinkError::InvalidFingerprint)
        );
    }

    #[test]
    fn stored_form_round_trips_through_json() {
        let link = validate_android_asset_link(input("com.chengming.termux", &[FP_A]))
            .expect("valid")
            .expect("declared");
        let encoded = serde_json::to_string(&link).expect("serializable");
        assert_eq!(
            serde_json::from_str::<AndroidAssetLink>(&encoded).expect("deserializable"),
            link
        );
    }
}
