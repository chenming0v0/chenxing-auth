//! 外部 IdP 出网用的 HTTP 客户端（Issue #291、#294）。
//!
//! 这个客户端是本服务唯一会向「管理员配置的任意 URL」发起请求的地方，因此它的
//! 构造参数本身就是安全边界的一部分，不能散落在调用点：
//!
//! 1. `no_proxy()` —— reqwest 的 `ClientBuilder` 默认 `auto_sys_proxy = true`，
//!    会读取 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`。一旦走代理，域名由代理解析、
//!    连接由代理建立，本地解析器筛查的地址就不再是实际连接目标，#291 的私网筛查
//!    整体失效（Issue #294）。这条边界不能依赖运维配置 `NO_PROXY` 来维持，必须在
//!    代码里关掉。需要经代理访问外部 IdP 的部署应改用出网网关，而不是让本服务
//!    把连接目标的决定权交给环境变量。
//! 2. `dns_resolver(PublicEndpointResolver)` —— 解析结果即建连地址，不留 DNS
//!    rebinding 时间窗；回环例外是否放行由传入的 [`EndpointPolicy`] 决定
//!    （Issue #343）。
//! 3. `redirect(none)` —— 重定向会把请求带到未经校验的新目标，等于绕过端点校验。
//! 4. `timeout` —— 外部 IdP 不可控，必须有上界。
//!
//! 构造函数是 `pub` 的，回归测试才能拿到与生产完全一致的客户端去证明代理确实
//! 被禁用；如果测试自己拼一份 builder，就只能证明测试代码的写法。

use std::{sync::Arc, time::Duration};

use reqwest::Client;

use super::endpoint_policy::{EndpointPolicy, PublicEndpointResolver};

/// 外部 IdP 请求超时。token 与 userinfo 都在浏览器回调路径上，不能无限等待。
pub const EXTERNAL_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// 构造 provider 专用出网客户端。
///
/// 失败只可能来自 TLS 后端初始化，调用方按「远端请求不可用」处理即可。
/// `policy` 决定回环例外是否放行：生产策略下回环解析结果直接让连接失败。
pub fn build_provider_http_client(policy: EndpointPolicy) -> reqwest::Result<Client> {
    Client::builder()
        .timeout(EXTERNAL_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // Issue #294：显式禁用系统代理。默认行为会读取 HTTP_PROXY/HTTPS_PROXY/
        // ALL_PROXY，把解析和建连都交给代理，使下面的解析器筛查失去意义。
        .no_proxy()
        // Issue #291：域名端点的实际指向只有解析后才知道。把筛查放进解析器，
        // 交出的地址就是随后建连使用的地址，不留 DNS rebinding 时间窗。
        // Issue #343：回环例外由策略门控，生产策略下 `localhost` 同样不可达。
        .dns_resolver(Arc::new(PublicEndpointResolver::new(policy)))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造本身必须成功：它在 `ExternalOAuthService::new` 里是启动路径的一部分。
    /// 代理是否真的被禁用由 `tests/oauth_provider_proxy_boundary.rs` 用真实连接证明。
    #[test]
    fn provider_client_builds() {
        build_provider_http_client(EndpointPolicy::PRODUCTION).expect("provider http client");
    }
}
