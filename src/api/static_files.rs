//! React 构建产物（`web/dist`）的静态托管与 SPA 回退。
//!
//! 后端只做静态托管，不生成或渲染任何 HTML：这里返回的 `index.html` 是
//! Vite 的构建产物，由 [`crate::web_dist::EMBEDDED_INDEX_HTML`] 在编译期内嵌，
//! 本模块不持有第二份定义。
//!
//! 请求的处理顺序是：
//! 1. `/index.html` 显式走 `web_app`，与 `/` 共用编译期内嵌的 SPA shell；
//! 2. `ServeDir` 命中产物根下的真实文件（JS / CSS / 图标等）时直接返回文件；
//! 3. 未命中时回退到 `web_app`，由它区分协议路径、静态资源路径和 SPA 路由。
//!
//! 静态根不在这里解析：它是启动期就 canonicalize 并校验过的 [`WebDistRoot`]
//! （Issue #303）。本模块因此没有任何「目录不存在」「配置为空」之类的降级分支——
//! 那些情况在进程开始监听之前就已经被拒绝。

use axum::{
    Router,
    extract::Request,
    http::{
        HeaderValue, Method, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
    routing::{MethodRouter, any},
};
use tower_http::services::ServeDir;

use crate::web_dist::{EMBEDDED_INDEX_HTML, WebDistRoot};

/// SPA shell 必须每次向源站再验证：新部署会换掉内嵌 `index.html` 引用的哈希资源，
/// 浏览器若继续用旧 shell 就会去拉已经不存在的 chunk。
const SPA_CACHE_CONTROL: &str = "no-cache";

/// Vite 内容哈希资源：文件名变了才是新内容，旧 URL 永不复用。
const HASHED_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// 构建静态文件服务。
///
/// `ServeDir` 负责产物根下的真实文件；文件缺失或方法不被允许时回退到
/// `web_app`，从而让 SPA 路由拿到 `index.html`、让资源路径拿到 JSON 404。
/// 外层 Router 只用来给哈希 assets 补 `Cache-Control`，不改变匹配顺序。
pub(super) fn static_service(root: &WebDistRoot) -> Router {
    Router::new()
        // `/index.html` 是内嵌 shell 的显式别名，不能让 ServeDir 读取磁盘副本。
        .route("/index.html", any(web_app))
        .fallback_service(
            ServeDir::new(root.path())
                // 目录请求不从磁盘拼 index.html，直接交给回退处理器：
                // 内嵌的 index.html 是 SPA shell 的唯一来源，避免磁盘副本与内嵌副本
                // 产生两条可能不一致的路径（磁盘产物可能比内嵌的旧），也顺带避免
                // SPA 路由撞上同名目录时被 301 重定向到带斜杠的地址。
                .append_index_html_on_directories(false)
                // 默认情况下 ServeDir 对非 GET/HEAD 直接返回 405，会绕过 web_app。
                // 打开该开关让所有方法都走同一条回退路径，保持 404 语义一致。
                .call_fallback_on_method_not_allowed(true)
                .fallback(spa_fallback()),
        )
        .layer(from_fn(cache_hashed_assets))
}

/// SPA 回退服务。
///
/// 状态类型显式固定为 `()`，因为 `web_app` 不提取 `AppState`。作为
/// `ServeDir` 的 fallback 时只有 `MethodRouter<()>` 才实现 `Service`，
/// 写死类型可以避免依赖类型推导。
fn spa_fallback() -> MethodRouter<()> {
    any(web_app)
}

/// `ServeDir` 未命中真实文件时的回退处理器，也是 `/index.html` 的唯一处理函数。
async fn web_app(request: axum::extract::Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return crate::error::not_found("not_found", "not found");
    }

    let path = request.uri().path();
    // 协议路径（API、真实 OAuth/OIDC 端点等）和带扩展名的资源路径都不应返回 SPA shell：
    // 前者会让客户端把 HTML 当 JSON 解析，后者会让缺失的 JS/CSS 静默变成 HTML。
    // `/index.html` 有扩展名，但它就是这份 shell 本身，必须与 `/` 走同一条路径。
    if !is_spa_document(path) && (is_protocol_path(path) || has_file_extension(path)) {
        return crate::error::not_found("not_found", "not found");
    }

    spa_shell()
}

fn spa_shell() -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, SPA_CACHE_CONTROL),
        ],
        EMBEDDED_INDEX_HTML,
    )
        .into_response()
}

/// 命中带内容哈希的 `/assets/*` 且源站 200 时，才标一年 immutable。
///
/// 404 不能 immutable，否则缺失的 chunk 会被中间缓存钉死。非哈希路径
/// （`/favicon.png`、`/fonts/*.woff2`、SPA shell）走各自的策略，这里不动。
async fn cache_hashed_assets(request: Request, next: Next) -> Response {
    let hashed = is_content_hashed_asset(request.uri().path());
    let mut response = next.run(request).await;
    if hashed && response.status() == StatusCode::OK {
        response.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static(HASHED_ASSET_CACHE_CONTROL),
        );
    }
    response
}

/// Vite 把带内容哈希的产物放在 `/assets/`，文件名形如 `name-<hash>.ext`。
///
/// 当前 `web/dist/assets/` 下全是这种文件（`index-*.js` / `index-*.css` /
/// `logo-*.png`）。根上的 `favicon.png`、`apple-touch-icon.png` 和
/// `/fonts/*.woff2` 没有哈希，不能按路径前缀一刀切。哈希是 8-12 位
/// `[0-9A-Za-z_-]`（Vite 默认 url-safe，可能含 `-`）。
fn is_content_hashed_asset(path: &str) -> bool {
    let Some(relative) = path.strip_prefix("/assets/") else {
        return false;
    };
    if relative.is_empty() || relative.ends_with('/') {
        return false;
    }
    hashed_filename(relative.rsplit('/').next().unwrap_or(relative))
}

fn hashed_filename(filename: &str) -> bool {
    let Some((stem, extension)) = filename.rsplit_once('.') else {
        return false;
    };
    if extension.is_empty() {
        return false;
    }
    let bytes = stem.as_bytes();
    (8..=12).any(|hash_len| {
        let Some(split) = bytes.len().checked_sub(hash_len) else {
            return false;
        };
        split >= 1
            && bytes[split - 1] == b'-'
            && bytes[split..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
    })
}

fn is_spa_document(path: &str) -> bool {
    path == "/" || path == "/index.html"
}

fn is_protocol_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || is_unregistered_oauth_path(path)
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.starts_with("/health/")
}

/// `/oauth/*` 默认是协议空间，只有前端实际注册的三个浏览器页才回退 SPA。
///
/// 依据 `web/src/App.tsx` 的 `pages` 表：只登记了精确路径
/// `/oauth/account`、`/oauth/consent`、`/oauth/redirect`，没有尾斜杠变体。
/// 尾斜杠（`/oauth/consent/`）和子路径（`/oauth/consent/xxx`）必须当协议 404，
/// 避免 OAuth 客户端把拼错的 URL 当成成功页。
fn is_unregistered_oauth_path(path: &str) -> bool {
    (path == "/oauth" || path.starts_with("/oauth/"))
        && !matches!(
            path,
            "/oauth/account" | "/oauth/consent" | "/oauth/redirect"
        )
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
            "/oauth",
            "/oauth/authorize",
            "/oauth/authorize/",
            "/oauth/token",
            "/oauth/token/",
            "/oauth/revoke",
            "/oauth/revoke/",
            "/oauth/userinfo",
            "/oauth/userinfo/",
            "/oauth/not-registered",
            "/oauth/does-not-exist",
            "/oauth/does-not-exist/",
            "/oauth/consent/xxx",
            "/oauth/consent/sub",
            "/oauth/account/",
            "/oauth/consent/",
            "/oauth/redirect/",
        ] {
            assert!(is_protocol_path(path), "{path}");
        }
        assert!(is_protocol_path("/.well-known/openid-configuration"));
        assert!(is_protocol_path("/health/ready"));

        // 前端 App.tsx 只注册无尾斜杠的精确路径，尾斜杠变体走协议 404。
        for path in ["/oauth/account", "/oauth/consent", "/oauth/redirect"] {
            assert!(!is_protocol_path(path), "{path}");
        }
        assert!(!is_protocol_path("/console"));
        assert!(!is_protocol_path("/assets/main.js"));
        assert!(!is_protocol_path("/admin/login"));
    }

    /// `/` 与 `/index.html` 是同一份文档；后者有扩展名，但不能当缺失资源 404。
    #[test]
    fn index_html_is_the_spa_document_not_a_missing_asset() {
        assert!(has_file_extension("/index.html"));
        assert!(is_spa_document("/"));
        assert!(is_spa_document("/index.html"));
        assert!(!is_spa_document("/favicon.ico"));
        assert!(!is_spa_document("/assets/index.js"));
    }

    /// 内嵌 shell 是唯一的 HTML 来源，静态根不参与 HTML 生成。
    #[test]
    fn the_embedded_shell_is_the_spa_html_source() {
        assert!(EMBEDDED_INDEX_HTML.contains("<div id=\"root\"></div>"));
    }

    #[test]
    fn content_hashed_assets_match_vite_filenames() {
        assert!(is_content_hashed_asset("/assets/index-D43JXjyl.js"));
        assert!(is_content_hashed_asset("/assets/index-Cx-ZuEpU.css"));
        assert!(is_content_hashed_asset("/assets/logo-Czd3JYMY.png"));
        assert!(is_content_hashed_asset("/assets/nested/chunk-AbCdef12.js"));

        assert!(!is_content_hashed_asset("/assets/"));
        assert!(!is_content_hashed_asset("/assets/missing-chunk.js"));
        assert!(!is_content_hashed_asset("/favicon.png"));
        assert!(!is_content_hashed_asset("/fonts/exo2-400-latin.woff2"));
        assert!(!is_content_hashed_asset("/console"));
        assert!(!is_content_hashed_asset("/"));
    }
}
