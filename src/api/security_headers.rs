//! 全局响应安全头。
//!
//! CSP 分两条策略，按响应自身的 `Content-Type` 选择，而不是按请求路径：
//! 浏览器只对「被当作文档解析」的响应执行 CSP，子资源（JS、CSS、图片）响应上的
//! CSP 头会被忽略。因此判定依据是响应是不是 HTML 文档，路径前缀是无关变量。
//!
//! 这样也避免了维护一份「哪些前缀算 API」的清单：新增路由不需要同步改这里，
//! 只要它不返回 `text/html` 就自动落到严格策略上。

use axum::{
    http::{HeaderMap, HeaderName, HeaderValue, header::CONTENT_TYPE},
    response::Response,
};

/// SPA 文档策略（`web/dist/index.html`）。
///
/// 逐条对应 React 产物的真实加载需求：
/// - `default-src 'self'`：字体（`/fonts/*.woff2`）、`connect-src` 的同源
///   `fetch`、`manifest`、`media` 等都由它兜底，无需单列。
/// - `script-src 'self'`：Vite 产物是同源带哈希的 ES module，`index.html` 里
///   没有内联 `<script>`，所以不需要 `'unsafe-inline'` 或 nonce；也没有
///   `eval`/`new Function`，不需要 `'unsafe-eval'`。
/// - `style-src 'self'`：Tailwind v4 在构建期产出单个同源 CSS 文件；React 的
///   `style` prop 走 CSSOM 而非 `style` 属性，不受 CSP 约束。
/// - `img-src`：`data:` 供 TOTP 绑定二维码（`QRCode.toDataURL`），`blob:` 供
///   头像上传前的本地取景预览（`URL.createObjectURL`）。
/// - `object-src 'none'` / `frame-src 'none'`：本站不嵌插件与子框架。
/// - `base-uri 'self'`：注入的 `<base>` 不能把相对 URL 指向外部源。
/// - `form-action 'self'`：表单只能提交回本站。OAuth 跳第三方走
///   `window.location.assign`（顶层导航），不受该指令限制。
/// - `frame-ancestors 'none'`：与 `X-Frame-Options: DENY` 同义，防点击劫持。
const DOCUMENT_CSP: &str = "default-src 'self'; \
script-src 'self'; \
style-src 'self'; \
img-src 'self' data: blob:; \
object-src 'none'; \
frame-src 'none'; \
base-uri 'self'; \
form-action 'self'; \
frame-ancestors 'none'";

/// 非文档响应策略（JSON API、图片、JS、CSS、重定向等）。
///
/// 这些响应不该有任何自主加载能力。浏览器直接导航到 JSON 端点时它会作为文档
/// 生效，`default-src 'none'` 让即便被误判成 HTML 的响应也无法执行脚本。
///
/// `base-uri`、`form-action`、`frame-ancestors` 不回退到 `default-src`，
/// 必须显式写出；其余指令由 `default-src 'none'` 覆盖。
const STRICT_CSP: &str = "default-src 'none'; \
base-uri 'none'; \
form-action 'none'; \
frame-ancestors 'none'";

const HSTS_POLICY: &str = "max-age=31536000; includeSubDomains";

pub(super) fn hsts_enabled(issuer_url: &str) -> bool {
    url::Url::parse(issuer_url).is_ok_and(|issuer| issuer.scheme() == "https")
}

pub(super) async fn apply(response: Response, hsts_enabled: bool) -> Response {
    let mut response = response;
    let policy = content_security_policy(response.headers());
    let headers = response.headers_mut();
    set_header(headers, "x-frame-options", "DENY");
    set_header(headers, "content-security-policy", policy);
    set_header(headers, "x-content-type-options", "nosniff");
    set_header(headers, "referrer-policy", "no-referrer");
    if hsts_enabled {
        set_header(headers, "strict-transport-security", HSTS_POLICY);
    }
    response
}

/// 只有 HTML 文档需要放宽到 SPA 策略，其余一律严格。
///
/// 缺失 `Content-Type` 的响应（304、重定向、空体错误）落到严格策略：它们没有
/// 可执行内容，收紧不会破坏任何东西。
fn content_security_policy(headers: &HeaderMap) -> &'static str {
    if is_html_document(headers) {
        DOCUMENT_CSP
    } else {
        STRICT_CSP
    }
}

fn is_html_document(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
        .is_some_and(|mime| mime.eq_ignore_ascii_case("text/html"))
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{HeaderValue, header::CONTENT_TYPE},
        response::Response,
    };

    use super::{DOCUMENT_CSP, STRICT_CSP, apply, hsts_enabled};

    fn response_with_content_type(content_type: &str) -> Response {
        let mut response = Response::new(Body::empty());
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("valid content type"),
        );
        response
    }

    #[test]
    fn hsts_follows_the_configured_issuer_scheme() {
        assert!(!hsts_enabled("http://127.0.0.1:3000"));
        assert!(hsts_enabled("https://auth.example.com"));
    }

    #[tokio::test]
    async fn http_responses_get_baseline_headers_without_hsts() {
        let response = apply(Response::new(Body::empty()), false).await;

        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response
                .headers()
                .get("strict-transport-security")
                .is_none()
        );
    }

    #[tokio::test]
    async fn https_responses_get_hsts() {
        let response = apply(Response::new(Body::empty()), true).await;

        assert_eq!(
            response.headers()["strict-transport-security"],
            "max-age=31536000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn html_documents_get_the_spa_policy() {
        let response = apply(
            response_with_content_type("text/html; charset=utf-8"),
            false,
        )
        .await;

        assert_eq!(response.headers()["content-security-policy"], DOCUMENT_CSP);
    }

    #[tokio::test]
    async fn the_spa_policy_covers_the_directives_the_react_build_actually_needs() {
        let response = apply(response_with_content_type("text/html"), false).await;
        let policy = response.headers()["content-security-policy"]
            .to_str()
            .expect("ASCII policy")
            .to_owned();

        // 同源兜底 + 无内联脚本：Vite 产物是同源带哈希的 ES module。
        assert!(policy.contains("default-src 'self'"), "{policy}");
        assert!(policy.contains("script-src 'self'"), "{policy}");
        assert!(!policy.contains("unsafe-inline"), "{policy}");
        assert!(!policy.contains("unsafe-eval"), "{policy}");
        // 二维码用 data:，头像取景预览用 blob:，缺一个就会退化成加载失败。
        assert!(policy.contains("img-src 'self' data: blob:"), "{policy}");
        // 这三条不回退到 default-src，必须显式出现。
        assert!(policy.contains("base-uri 'self'"), "{policy}");
        assert!(policy.contains("form-action 'self'"), "{policy}");
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
        assert!(policy.contains("object-src 'none'"), "{policy}");
    }

    #[tokio::test]
    async fn json_api_responses_get_the_strict_policy() {
        let response = apply(response_with_content_type("application/json"), false).await;

        assert_eq!(response.headers()["content-security-policy"], STRICT_CSP);
        let policy = response.headers()["content-security-policy"]
            .to_str()
            .expect("ASCII policy");
        assert!(policy.contains("default-src 'none'"), "{policy}");
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    }

    #[tokio::test]
    async fn assets_and_avatars_get_the_strict_policy() {
        // 子资源响应上的 CSP 被浏览器忽略，直接导航到它时严格策略才是正确默认值。
        for content_type in [
            "application/javascript",
            "text/css",
            "image/jpeg",
            "font/woff2",
        ] {
            let response = apply(response_with_content_type(content_type), false).await;
            assert_eq!(
                response.headers()["content-security-policy"],
                STRICT_CSP,
                "{content_type}"
            );
        }
    }

    #[tokio::test]
    async fn responses_without_a_content_type_get_the_strict_policy() {
        // 重定向和空体错误没有可执行内容，收紧不破坏行为。
        let response = apply(Response::new(Body::empty()), false).await;

        assert_eq!(response.headers()["content-security-policy"], STRICT_CSP);
    }

    #[tokio::test]
    async fn html_detection_ignores_parameters_and_case() {
        for content_type in ["TEXT/HTML", "text/html ; charset=utf-8", "Text/Html"] {
            let response = apply(response_with_content_type(content_type), false).await;
            assert_eq!(
                response.headers()["content-security-policy"],
                DOCUMENT_CSP,
                "{content_type}"
            );
        }

        // 前缀相同但不是 HTML 文档，不能误放宽。
        for content_type in ["text/html-fragment", "application/xhtml+xml", "text/plain"] {
            let response = apply(response_with_content_type(content_type), false).await;
            assert_eq!(
                response.headers()["content-security-policy"],
                STRICT_CSP,
                "{content_type}"
            );
        }
    }
}
