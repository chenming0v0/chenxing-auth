//! Android App Links 声明（`/.well-known/assetlinks.json`）。
//!
//! 辰星域名被移动端 OAuth 客户端（如 termux-chrome）用作 HTTPS 回调落地链接；
//! Android 只有在链接域名下取到列有该 App 包名和签名指纹的 assetlinks.json 后，
//! 才会把回调链接直接交给 App 而不是浏览器。声明内容由 `ANDROID_ASSETLINKS`
//! 生成，新增 App 只需追加一条配置，不需要改代码或部署产物。
//!
//! 格式：以逗号或空白分隔的多个 `包名:SHA-256指纹`，指纹接受带冒号或不带冒号
//! 的 64 位十六进制，大小写不敏感，输出统一为 Google 文档采用的大写冒号分隔。
//! 同一包名可重复出现（多套签名，如调试签名和发布签名），会合并到同一条目。
//! 未设置或为空表示不发布声明，端点返回 404。

use std::env;

use serde::Serialize;

use super::ConfigError;

const ANDROID_ASSETLINKS_ENV: &str = "ANDROID_ASSETLINKS";
const APP_LINKS_RELATION: &str = "delegate_permission/common.handle_all_urls";
const ANDROID_APP_NAMESPACE: &str = "android_app";
const SHA256_FINGERPRINT_BYTES: usize = 32;

/// 一个可以接管辰星域名 App Link 的 Android 应用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidApp {
    pub package_name: String,
    /// 大写、冒号分隔的 SHA-256 签名指纹，按配置顺序去重。
    pub sha256_cert_fingerprints: Vec<String>,
}

/// 已解析并验证的 App Links 声明集合，按配置中首次出现的顺序保存。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidAssetLinks {
    apps: Vec<AndroidApp>,
}

#[derive(Serialize)]
struct Statement<'a> {
    relation: [&'static str; 1],
    target: Target<'a>,
}

#[derive(Serialize)]
struct Target<'a> {
    namespace: &'static str,
    package_name: &'a str,
    sha256_cert_fingerprints: &'a [String],
}

impl AndroidAssetLinks {
    pub fn apps(&self) -> &[AndroidApp] {
        &self.apps
    }

    /// 渲染为 Digital Asset Links 语句数组。
    pub fn to_json(&self) -> String {
        let statements: Vec<Statement<'_>> = self
            .apps
            .iter()
            .map(|app| Statement {
                relation: [APP_LINKS_RELATION],
                target: Target {
                    namespace: ANDROID_APP_NAMESPACE,
                    package_name: &app.package_name,
                    sha256_cert_fingerprints: &app.sha256_cert_fingerprints,
                },
            })
            .collect();
        serde_json::to_string(&statements).expect("assetlinks statements are plain data")
    }
}

pub fn android_assetlinks_from_env() -> Result<Option<AndroidAssetLinks>, ConfigError> {
    parse_android_assetlinks(&env::var(ANDROID_ASSETLINKS_ENV).unwrap_or_default())
}

pub fn parse_android_assetlinks(raw: &str) -> Result<Option<AndroidAssetLinks>, ConfigError> {
    let mut apps: Vec<AndroidApp> = Vec::new();
    for entry in raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|entry| !entry.is_empty())
    {
        let (package_name, fingerprint) = entry
            .split_once(':')
            .ok_or(ConfigError::InvalidValue(ANDROID_ASSETLINKS_ENV))?;
        if !is_android_package_name(package_name) {
            return Err(ConfigError::InvalidValue(ANDROID_ASSETLINKS_ENV));
        }
        let fingerprint = normalize_fingerprint(fingerprint)
            .ok_or(ConfigError::InvalidValue(ANDROID_ASSETLINKS_ENV))?;
        match apps.iter_mut().find(|app| app.package_name == package_name) {
            Some(app) => {
                if !app.sha256_cert_fingerprints.contains(&fingerprint) {
                    app.sha256_cert_fingerprints.push(fingerprint);
                }
            }
            None => apps.push(AndroidApp {
                package_name: package_name.to_owned(),
                sha256_cert_fingerprints: vec![fingerprint],
            }),
        }
    }
    if apps.is_empty() {
        return Ok(None);
    }
    Ok(Some(AndroidAssetLinks { apps }))
}

/// Android 包名：至少两段、点分隔的 Java 标识符（ASCII 字母开头，字母数字下划线）。
fn is_android_package_name(value: &str) -> bool {
    let mut segments = 0;
    for segment in value.split('.') {
        let mut chars = segment.chars();
        let valid_head = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
        if !valid_head || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

/// 接受 `AA:BB:…`、`aabb…` 两种写法，输出大写冒号分隔。
fn normalize_fingerprint(value: &str) -> Option<String> {
    let hex: Vec<u8> = value
        .bytes()
        .filter(|byte| *byte != b':')
        .map(|byte| byte.to_ascii_uppercase())
        .collect();
    if hex.len() != SHA256_FINGERPRINT_BYTES * 2 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let pairs: Vec<&str> = hex
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("ascii hex digits"))
        .collect();
    Some(pairs.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
    const FP_B_PLAIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn empty_or_whitespace_disables_publication() {
        assert_eq!(parse_android_assetlinks(""), Ok(None));
        assert_eq!(parse_android_assetlinks(" , \n"), Ok(None));
    }

    #[test]
    fn single_entry_renders_google_statement_shape() {
        let links = parse_android_assetlinks(&format!("com.chengming.termux:{FP_A}"))
            .expect("valid")
            .expect("published");
        assert_eq!(
            links.to_json(),
            format!(
                "[{{\"relation\":[\"{APP_LINKS_RELATION}\"],\"target\":{{\"namespace\":\"android_app\",\"package_name\":\"com.chengming.termux\",\"sha256_cert_fingerprints\":[\"{FP_A}\"]}}}}]"
            )
        );
    }

    #[test]
    fn fingerprints_are_normalized_and_grouped_per_package() {
        let raw = format!(
            "com.chengming.termux:{FP_A}, com.example.visa:{FP_B_PLAIN}\ncom.chengming.termux:{}",
            FP_B_PLAIN.to_uppercase()
        );
        let links = parse_android_assetlinks(&raw)
            .expect("valid")
            .expect("published");
        let fp_b_colon = FP_B_PLAIN
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            links.apps(),
            &[
                AndroidApp {
                    package_name: "com.chengming.termux".to_owned(),
                    sha256_cert_fingerprints: vec![FP_A.to_owned(), fp_b_colon.clone()],
                },
                AndroidApp {
                    package_name: "com.example.visa".to_owned(),
                    sha256_cert_fingerprints: vec![fp_b_colon],
                },
            ]
        );
    }

    #[test]
    fn duplicate_fingerprint_for_same_package_is_collapsed() {
        let raw = format!("com.a.b:{FP_A},com.a.b:{}", FP_A.to_lowercase());
        let links = parse_android_assetlinks(&raw)
            .expect("valid")
            .expect("published");
        assert_eq!(
            links.apps()[0].sha256_cert_fingerprints,
            vec![FP_A.to_owned()]
        );
    }

    #[test]
    fn malformed_entries_are_rejected() {
        for raw in [
            "com.chengming.termux",
            &format!("termux:{FP_A}"),
            &format!("com.1bad.pkg:{FP_A}"),
            &format!("com.bad-pkg.app:{FP_A}"),
            &format!("com.a.b:{}", &FP_A[..FP_A.len() - 3]),
            &format!("com.a.b:{}", FP_A.replace('4', "G")),
            "com.a.b:",
        ] {
            assert_eq!(
                parse_android_assetlinks(raw),
                Err(ConfigError::InvalidValue(ANDROID_ASSETLINKS_ENV)),
                "{raw}"
            );
        }
    }
}
