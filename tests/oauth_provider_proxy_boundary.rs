//! Issue #294：provider 出网客户端必须无视系统代理环境变量。
//!
//! 为什么这条边界需要真实连接来证明：reqwest 的 `ClientBuilder` 默认
//! `auto_sys_proxy = true`，会在 `build()` 时读取 `HTTP_PROXY`、`HTTPS_PROXY`、
//! `ALL_PROXY`。走代理后域名由代理解析、连接由代理建立，`PublicEndpointResolver`
//! 筛查的地址就不再是实际连接目标，#291 的私网/DNS rebinding 防护整体失效。
//! reqwest 不暴露「这个 Client 配了哪些代理」的读接口，所以唯一诚实的证明方式是
//! 让本地监听器充当代理，看它有没有收到连接。
//!
//! 用例结构是「对照 + 被测」，两者在同一份环境变量下跑：
//!
//! - 对照客户端不调用 `no_proxy()`，必须命中监听器。它证明的是这套夹具确实能
//!   观测到代理被使用——否则「被测客户端没命中」可能只是夹具本身失效。
//! - 被测客户端来自 `build_provider_http_client()`，与生产完全同一份构造，
//!   必须一次都不命中监听器。
//!
//! 判定不用「计数器 + 事后读」，而是把 `accept()` 和请求放进同一个 `select!`：
//! 谁先完成谁说明真相。计数器要依赖后台任务被调度到，在单线程运行时下时序不稳。
//!
//! 环境变量在建任何客户端之前设置，且这个测试二进制里只有本用例读写 environ。

use std::{net::SocketAddr, time::Duration};

use chenxing_auth::oauth::providers::{
    endpoint_policy::EndpointPolicy, http_client::build_provider_http_client,
};
use tokio::net::TcpListener;

/// 代理环境变量指向的目标主机。`.invalid` 是 RFC 2606 保留 TLD，保证不存在真实
/// 解析结果：不走代理时解析必然失败，用例不依赖外网可达性。
const TARGET_URL: &str = "https://idp.invalid/oauth/token";

/// 单次判定的上界。走代理时 `accept()` 立即完成，不走代理时解析在毫秒级失败，
/// 因此这个值只是兜底，不是正常路径的等待时间。
const DECISION_TIMEOUT: Duration = Duration::from_secs(3);

/// 判定完一轮后清空 backlog 的静默窗口。
const DRAIN_WINDOW: Duration = Duration::from_millis(100);

/// 请求这一发是否落到了充当代理的监听器上。
///
/// 三方竞争，取最先完成的：
/// - `accept()` 完成 → 客户端连了代理，`true`。
/// - 请求先返回（必然是错误：`.invalid` 无法解析）→ 没连代理，`false`。
/// - 超时 → 既没连上代理也没失败，同样按没连代理处理，由调用方的其余断言兜底。
///
/// `accept()` 是 cancel-safe 的，被 `select!` 丢掉不会吃掉已建立的连接。
async fn hits_proxy(client: &reqwest::Client, listener: &TcpListener) -> bool {
    tokio::select! {
        biased;
        accepted = listener.accept() => {
            accepted.expect("accept proxy connection");
            true
        }
        _ = client.get(TARGET_URL).send() => false,
        _ = tokio::time::sleep(DECISION_TIMEOUT) => false,
    }
}

/// 清空 backlog 里可能残留的连接。
///
/// 两轮判定之间必须做这一步：上一轮客户端有可能开了多于一条连接（连接池预热、
/// 重试），残留在 backlog 里会让下一轮的 `accept()` 立刻完成，把「没走代理」
/// 误判成「走了代理」。
async fn drain(listener: &TcpListener) {
    while tokio::time::timeout(DRAIN_WINDOW, listener.accept())
        .await
        .is_ok()
    {}
}

/// 出网客户端的构造是安全边界，不能被「顺手挪个 builder 选项」改掉。
///
/// 与下面的连接用例互补：连接用例证明当前行为正确，这条锁住四项约束必须留在同一个
/// 构造函数里。把 `no_proxy()` 挪到调用点，就等于给漏掉它的新调用点开了口子。
/// 本用例只读编译期字符串，不触碰环境变量，与下面的用例并行也不产生 environ 竞争。
#[test]
fn provider_client_construction_keeps_all_egress_guards() {
    const HTTP_CLIENT: &str = include_str!("../src/oauth/providers/http_client.rs");
    for guard in [
        ".no_proxy()",
        ".dns_resolver(Arc::new(PublicEndpointResolver::new(policy)))",
        ".redirect(reqwest::redirect::Policy::none())",
        ".timeout(EXTERNAL_HTTP_TIMEOUT)",
    ] {
        assert!(
            HTTP_CLIENT.contains(guard),
            "provider 出网客户端缺少出网约束：{guard}"
        );
    }
}

/// 生产客户端不得读取 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`。
#[tokio::test(flavor = "current_thread")]
async fn provider_client_ignores_system_proxy_environment() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind proxy listener");
    let proxy_address: SocketAddr = listener.local_addr().expect("proxy listener address");
    let proxy_url = format!("http://{proxy_address}");
    // SAFETY: 此刻进程内没有其他线程读写环境变量——运行时是 current_thread，
    // 本测试二进制里只有本用例访问 environ，且设置发生在建任何客户端之前。
    // Rust 2024 起 `set_var` 需要 `unsafe`，正是为了让这个前提显式写出来。
    unsafe {
        std::env::set_var("HTTP_PROXY", &proxy_url);
        std::env::set_var("HTTPS_PROXY", &proxy_url);
        std::env::set_var("ALL_PROXY", &proxy_url);
        // NO_PROXY 是运维旁路，不能让它替被测代码把边界撑住。
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    }

    // 对照：默认 builder 采纳环境变量里的代理，必须命中监听器。
    let control = reqwest::Client::builder().build().expect("control client");
    assert!(
        hits_proxy(&control, &listener).await,
        "夹具失效：默认客户端都没有走代理，本用例无法证明任何事情"
    );
    drain(&listener).await;

    // 被测：生产构造必须完全绕开代理，走本地解析器并在解析阶段失败。
    let hardened =
        build_provider_http_client(EndpointPolicy::PRODUCTION).expect("provider http client");
    assert!(
        !hits_proxy(&hardened, &listener).await,
        "provider 客户端读取了系统代理：SSRF 筛查的地址不再是实际连接目标"
    );

    // 不经代理时目标必须真的连不上：`.invalid` 没有解析结果，请求应当直接失败。
    // 这条排除「请求根本没发出去」这种假阴性。
    let direct = tokio::time::timeout(DECISION_TIMEOUT, hardened.get(TARGET_URL).send())
        .await
        .expect("provider 请求应在解析阶段快速失败：检查本机 DNS 是否劫持 .invalid");
    assert!(
        direct.is_err(),
        "provider 客户端不得连上任何目标：`.invalid` 不存在解析结果"
    );
}
