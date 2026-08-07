//! React 构建产物（`web/dist`）的静态托管与 SPA 回退。
//!
//! 后端只做静态托管，不生成或渲染任何 HTML：这里返回的 `index.html` 是
//! Vite 的构建产物，在编译期通过 `include_str!` 内嵌。
//!
//! 请求的处理顺序是：
//! 1. `ServeDir` 命中 `web/dist` 下的真实文件（JS / CSS / 图标等）时直接返回文件；
//! 2. 未命中时回退到 `web_app`，由它区分协议路径、静态资源路径和 SPA 路由。

use axum::{
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{MethodRouter, any},
};
use std::{env, path::PathBuf};
use tower_http::services::ServeDir;

/// 默认静态资源目录，相对于进程工作目录解析。
const DEFAULT_WEB_DIST_DIR: &str = "web/dist";

/// 构建静态文件服务。
///
/// `ServeDir` 负责 `web/dist` 下的真实文件；文件缺失或方法不被允许时回退到
/// `web_app`，从而让 SPA 路由拿到 `index.html`、让资源路径拿到 JSON 404。
pub(super) fn static_service() -> ServeDir<MethodRouter<()>> {
    let dist_dir = web_dist_dir();

    // 目录缺失不 panic：`index.html` 已在编译期内嵌，SPA 回退仍然可用，
    // 静态资源退化为 404 是可接受的降级，比启动失败更适合线上。
    if !dist_dir.is_dir() {
        tracing::warn!(
            event = "web_dist_missing",
            path = %dist_dir.display(),
            "静态资源目录不存在，JS/CSS 将返回 404；SPA 回退仍可工作"
        );
    }

    ServeDir::new(dist_dir)
        // 目录请求不从磁盘拼 index.html，直接交给回退处理器：
        // 内嵌的 index.html 是 SPA shell 的唯一来源，避免磁盘副本与内嵌副本
        // 产生两条可能不一致的路径（磁盘产物可能比内嵌的旧），也顺带避免
        // SPA 路由撞上同名目录时被 301 重定向到带斜杠的地址。
        .append_index_html_on_directories(false)
        // 默认情况下 ServeDir 对非 GET/HEAD 直接返回 405，会绕过 web_app。
        // 打开该开关让所有方法都走同一条回退路径，保持 404 语义一致。
        .call_fallback_on_method_not_allowed(true)
        .fallback(spa_fallback())
}

/// SPA 回退服务。
///
/// 状态类型显式固定为 `()`，因为 `web_app` 不提取 `AppState`。作为
/// `ServeDir` 的 fallback 时只有 `MethodRouter<()>` 才实现 `Service`，
/// 写死类型可以避免依赖类型推导。
fn spa_fallback() -> MethodRouter<()> {
    any(web_app)
}

/// 解析静态资源目录路径，支持环境变量覆盖以应对单二进制部署场景。
///
/// 单二进制部署时进程工作目录不一定是仓库根目录，`web/dist` 这种相对路径会
/// 找不到，所以允许用 `WEB_DIST_DIR` 指定绝对路径。
///
/// 这里直接读环境变量而不是走 `AppConfig`：`router()` 目前是同步构造且不接受
/// 额外参数，把该路径塞进 `AppConfig` 会牵动配置加载和所有调用点。
/// TODO: 后续应把该路径收敛进 `AppConfig` 统一管理。
fn web_dist_dir() -> PathBuf {
    resolve_web_dist_dir(env::var("WEB_DIST_DIR").ok())
}

/// 纯函数形式的目录解析规则，便于在不改动进程环境变量的前提下测试。
///
/// 空值按“未配置”处理：`ServeDir::new("")` 会把整个工作目录暴露成静态根，
/// 那样 `.env`、私钥等文件都可能被下载，必须避免。
fn resolve_web_dist_dir(configured: Option<String>) -> PathBuf {
    configured
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WEB_DIST_DIR.to_owned())
        .into()
}

/// `ServeDir` 未命中真实文件时的回退处理器。
async fn web_app(request: axum::extract::Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let path = request.uri().path();
    // 协议路径（API、真实 OAuth/OIDC 端点等）和带扩展名的资源路径都不应返回 SPA shell：
    // 前者会让客户端把 HTML 当 JSON 解析，后者会让缺失的 JS/CSS 静默变成 HTML。
    if is_protocol_path(path) || has_file_extension(path) {
        return crate::error::not_found("not_found", "not found");
    }

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/dist/index.html")),
    )
        .into_response()
}

fn is_protocol_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || matches!(
            path,
            "/oauth/authorize" | "/oauth/token" | "/oauth/revoke" | "/oauth/userinfo"
        )
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.starts_with("/health/")
}

fn has_file_extension(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment
            .rsplit_once('.')
            .is_some_and(|(_, extension)| !extension.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_file_extension_recognizes_common_asset_patterns() {
        // Vite 产物的带哈希文件名是本 issue 的核心场景
        assert!(has_file_extension("/assets/index-D43JXjyl.js"));
        assert!(has_file_extension("/assets/index-Cx-ZuEpU.css"));
        assert!(has_file_extension("/favicon.ico"));
        assert!(has_file_extension("/robots.txt"));

        // SPA 路由没有扩展名
        assert!(!has_file_extension("/console"));
        assert!(!has_file_extension("/console/developer"));

        // 尾随斜杠不算文件扩展名
        assert!(!has_file_extension("/assets/"));

        // 点号开头的路径段（`.well-known`）会被判定为带扩展名，但它同时命中
        // is_protocol_path，web_app 两种判定都返回 JSON 404，最终行为仍然正确。
        assert!(has_file_extension("/.well-known"));
        assert!(!has_file_extension("/.well-known/openid-configuration"));
    }

    #[test]
    fn is_protocol_path_recognizes_api_oauth_wellknown_prefixes() {
        assert!(is_protocol_path("/api"));
        assert!(is_protocol_path("/api/v1/users"));
        for path in [
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/revoke",
            "/oauth/userinfo",
        ] {
            assert!(is_protocol_path(path), "{path}");
        }
        assert!(is_protocol_path("/.well-known/openid-configuration"));
        assert!(is_protocol_path("/health/ready"));

        // 其他路径交给文件服务或 SPA 处理
        for path in ["/oauth/account", "/oauth/consent", "/oauth/redirect"] {
            assert!(!is_protocol_path(path), "{path}");
        }
        assert!(!is_protocol_path("/console"));
        assert!(!is_protocol_path("/assets/main.js"));
        assert!(!is_protocol_path("/admin/login"));
    }

    #[test]
    fn resolve_web_dist_dir_uses_configured_value_when_present() {
        assert_eq!(
            resolve_web_dist_dir(Some("/opt/app/dist".to_owned())),
            PathBuf::from("/opt/app/dist")
        );
    }

    #[test]
    fn resolve_web_dist_dir_falls_back_to_default_when_none() {
        assert_eq!(
            resolve_web_dist_dir(None),
            PathBuf::from(DEFAULT_WEB_DIST_DIR)
        );
    }

    #[test]
    fn resolve_web_dist_dir_rejects_empty_string_for_security() {
        // 空字符串会让 ServeDir 把整个工作目录当静态根，
        // .env 和私钥等敏感文件都可能被下载，必须回落到默认值
        assert_eq!(
            resolve_web_dist_dir(Some("".to_owned())),
            PathBuf::from(DEFAULT_WEB_DIST_DIR)
        );
        assert_eq!(
            resolve_web_dist_dir(Some("   ".to_owned())),
            PathBuf::from(DEFAULT_WEB_DIST_DIR)
        );
    }
}
