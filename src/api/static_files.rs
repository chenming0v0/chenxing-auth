//! React 构建产物（`web/dist`）的静态托管与 SPA 回退。
//!
//! 后端只做静态托管，不生成或渲染任何 HTML：这里返回的 `index.html` 是
//! Vite 的构建产物，由 [`crate::web_dist::EMBEDDED_INDEX_HTML`] 在编译期内嵌，
//! 本模块不持有第二份定义。
//!
//! 请求的处理顺序是：
//! 1. `ServeDir` 命中产物根下的真实文件（JS / CSS / 图标等）时直接返回文件；
//! 2. 未命中时回退到 `web_app`，由它区分协议路径、静态资源路径和 SPA 路由。
//!
//! 静态根不在这里解析：它是启动期就 canonicalize 并校验过的 [`WebDistRoot`]
//! （Issue #303）。本模块因此没有任何「目录不存在」「配置为空」之类的降级分支——
//! 那些情况在进程开始监听之前就已经被拒绝。

use axum::{
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{MethodRouter, any},
};
use tower_http::services::ServeDir;

use crate::web_dist::{EMBEDDED_INDEX_HTML, WebDistRoot};

/// 构建静态文件服务。
///
/// `ServeDir` 负责产物根下的真实文件；文件缺失或方法不被允许时回退到
/// `web_app`，从而让 SPA 路由拿到 `index.html`、让资源路径拿到 JSON 404。
pub(super) fn static_service(root: &WebDistRoot) -> ServeDir<MethodRouter<()>> {
    ServeDir::new(root.path())
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
        EMBEDDED_INDEX_HTML,
    )
        .into_response()
}

fn is_protocol_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || matches!(
            path,
            "/oauth/authorize"
                | "/oauth/authorize/"
                | "/oauth/token"
                | "/oauth/token/"
                | "/oauth/revoke"
                | "/oauth/revoke/"
                | "/oauth/userinfo"
                | "/oauth/userinfo/"
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
            "/oauth/authorize/",
            "/oauth/token",
            "/oauth/token/",
            "/oauth/revoke",
            "/oauth/revoke/",
            "/oauth/userinfo",
            "/oauth/userinfo/",
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

    /// 内嵌 shell 是唯一的 HTML 来源，静态根不参与 HTML 生成。
    #[test]
    fn the_embedded_shell_is_the_spa_html_source() {
        assert!(EMBEDDED_INDEX_HTML.contains("<div id=\"root\"></div>"));
    }
}
