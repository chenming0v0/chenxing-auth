//! 路由级 CSRF 覆盖测试：让「漏掉 CSRF 校验」在 CI 里挂掉，而不是等线上被利用。
//!
//! `src/api/extract.rs` 用类型约束表达了「浏览器写操作必须校验 CSRF」，
//! 但类型只覆盖「handler 声明了提取器」这一半；另一半是「新增的写路由确实
//! 声明了提取器」。本测试扫描应用路由和 system router 的全部路由表，对每个
//! 状态改变方法（POST/PUT/PATCH/DELETE）要求二者之一：
//!
//! 1. handler 签名里有 [`SessionWrite`] 或 [`AdminWrite`]（类型级保证）；
//! 2. 该路径+方法出现在下面的 [`EXEMPTIONS`] 白名单里，并写明豁免依据。
//!
//! 白名单是**显式**的：新增写路由默认不合规，必须要么加提取器，要么在这里
//! 补一条带理由的豁免。反向断言同时保证白名单不会攒下与真实路由脱节的死条目。

use std::{collections::BTreeMap, fs, path::Path};

const ROUTE_SOURCES: [&str; 2] = [
    include_str!("../src/api/routes.rs"),
    include_str!("../src/api/mod.rs"),
];

/// 需要 CSRF 保证的 HTTP 方法。GET/HEAD 不改状态，同源策略也拿不到响应体。
const STATE_CHANGING: [&str; 4] = ["post", "put", "patch", "delete"];

/// 路由表里可能出现的方法构造器，用于把 `.route(...)` 拆成方法粒度。
const ROUTING_METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];

/// 提供类型级 CSRF 保证的提取器。
const WRITE_GUARDS: [&str; 2] = ["SessionWrite", "AdminWrite"];

/// 豁免依据。每个变体都是一条安全论证，而不是「暂时没改」的借口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exempt {
    /// 登录前的公开端点：此时浏览器没有任何可被借用的凭据。
    PublicEndpoint,
    /// 凭据不是浏览器自动附带的（Client 认证、`Authorization: Bearer`）。
    NonBrowserCredential,
    /// 登录票据阶段：Cookie 是 `SameSite=Lax` 的短时票据，且请求必须附带
    /// 攻击者拿不到的第二因子证明（TOTP 码或 WebAuthn 断言）。
    PreAuthTicket,
    /// OAuth 前端信道：协议要求浏览器顶层导航直达，授权码只回落到已注册
    /// 的 redirect_uri，真正的授权决定在带 CSRF 校验的决定端点完成。
    FrontChannelProtocol,
}

/// 状态改变路由的 CSRF 豁免白名单：`(路径, 方法, 依据)`。
const EXEMPTIONS: [(&str, &str, Exempt); 12] = [
    // —— OAuth 协议端点 ——
    ("/oauth/authorize", "post", Exempt::FrontChannelProtocol),
    ("/oauth/token", "post", Exempt::NonBrowserCredential),
    ("/oauth/revoke", "post", Exempt::NonBrowserCredential),
    ("/oauth/userinfo", "post", Exempt::NonBrowserCredential),
    // —— 登录前的公开端点 ——
    ("/api/v1/users", "post", Exempt::PublicEndpoint),
    ("/api/v1/auth/login", "post", Exempt::PublicEndpoint),
    ("/api/v1/admin/bootstrap", "post", Exempt::PublicEndpoint),
    // —— 登录票据阶段的第二因子 ——
    ("/api/v1/auth/totp/setup", "post", Exempt::PreAuthTicket),
    (
        "/api/v1/auth/totp/setup/confirm",
        "post",
        Exempt::PreAuthTicket,
    ),
    ("/api/v1/auth/totp/login", "post", Exempt::PreAuthTicket),
    (
        "/api/v1/auth/passkeys/register/finish",
        "post",
        Exempt::PreAuthTicket,
    ),
    (
        "/api/v1/auth/passkeys/authentication/finish",
        "post",
        Exempt::PreAuthTicket,
    ),
];

/// `PreAuthTicket` 豁免中仅换取挑战、不落地凭据变更的 start 端点。
/// 单独列出是为了让 start/finish 的差异在白名单里可见。
const PRE_AUTH_START: [(&str, &str, Exempt); 2] = [
    (
        "/api/v1/auth/passkeys/register/start",
        "post",
        Exempt::PreAuthTicket,
    ),
    (
        "/api/v1/auth/passkeys/authentication/start",
        "post",
        Exempt::PreAuthTicket,
    ),
];

/// 路由表里的一个「路径 + 方法 + handler」三元组。
#[derive(Debug)]
struct Endpoint {
    path: String,
    method: String,
    handler: String,
}

/// 一个 handler 的源码切片：签名与完整函数体。
struct Handler {
    signature: String,
}

fn exemption(path: &str, method: &str) -> Option<Exempt> {
    EXEMPTIONS
        .iter()
        .chain(PRE_AUTH_START.iter())
        .find(|(exempt_path, exempt_method, _)| *exempt_path == path && *exempt_method == method)
        .map(|(_, _, reason)| *reason)
}

/// 找到 `open` 处左括号对应的右括号下标，跳过字符串字面量内的括号。
fn matching_paren(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// 取 `.route(...)` 的第一个字符串字面量作为路径。
fn route_path(arguments: &str) -> Option<String> {
    let start = arguments.find('"')? + 1;
    let end = arguments[start..].find('"')? + start;
    Some(arguments[start..end].to_owned())
}

/// 从 `.route()` 的剩余实参里解析 `get(handler).post(handler)` 这类方法链。
///
/// 只认「方法名紧跟左括号」的形式；`axum::routing::put` 这种全限定写法在
/// 去掉路径实参后同样以方法名结尾，因此按标识符边界匹配即可覆盖两种风格。
fn method_handlers(arguments: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for method in ROUTING_METHODS {
        let mut cursor = 0;
        while let Some(offset) = arguments[cursor..].find(&format!("{method}(")) {
            let at = cursor + offset;
            cursor = at + method.len();
            let preceded_by_identifier = arguments[..at]
                .chars()
                .next_back()
                .is_some_and(|character| character.is_alphanumeric() || character == '_');
            if preceded_by_identifier {
                continue;
            }
            let Some(close) = matching_paren(arguments, cursor) else {
                continue;
            };
            let handler = arguments[cursor + 1..close].trim();
            let handler = handler.rsplit("::").next().unwrap_or(handler).trim();
            if !handler.is_empty() && !handler.contains(['(', '"']) {
                found.push((method.to_owned(), handler.to_owned()));
            }
        }
    }
    found
}

/// 解析应用路由和 system router，展开成方法粒度的端点列表。
fn endpoints() -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    for routes in ROUTE_SOURCES {
        let mut cursor = 0;
        while let Some(offset) = routes[cursor..].find(".route(") {
            let open = cursor + offset + ".route".len();
            cursor = open + 1;
            let Some(close) = matching_paren(routes, open) else {
                continue;
            };
            let arguments = &routes[open + 1..close];
            let Some(path) = route_path(arguments) else {
                continue;
            };
            let rest = &arguments[arguments.find(&path).unwrap_or_default() + path.len()..];
            for (method, handler) in method_handlers(rest) {
                endpoints.push(Endpoint {
                    path: path.clone(),
                    method,
                    handler,
                });
            }
        }
    }
    endpoints
}

/// 递归收集 `src` 下的 Rust 源码。
fn sources(directory: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("readable source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(fs::read_to_string(&path).expect("readable source file"));
        }
    }
}

/// 收集所有顶层 `async fn`；路由表决定其中哪些函数是 axum handler。
///
/// 只认行首（可带 `pub` / `pub(crate)`）的定义：impl 块里的方法有缩进，
/// 因此 `KeyManager::revoke` 之类的同名方法不会与 handler 混淆。
fn handlers() -> BTreeMap<String, Handler> {
    let mut files = Vec::new();
    sources(Path::new("src"), &mut files);

    let mut handlers: BTreeMap<String, Handler> = BTreeMap::new();
    for source in &files {
        let mut cursor = 0;
        while let Some(offset) = source[cursor..].find("async fn ") {
            let at = cursor + offset;
            cursor = at + "async fn ".len();
            let line_start = source[..at].rfind('\n').map_or(0, |index| index + 1);
            let prefix = &source[line_start..at];
            if !matches!(prefix, "" | "pub " | "pub(crate) " | "pub(super) ") {
                continue;
            }
            let name_start = cursor;
            let name_end = name_start
                + source[name_start..]
                    .find('(')
                    .unwrap_or(source.len() - name_start);
            let name = source[name_start..name_end].trim();
            let end = source[name_start..]
                .find("\n}\n")
                .map_or(source.len(), |index| name_start + index);
            let text = &source[line_start..end];
            let Some(arrow) = text.find(") -> ") else {
                continue;
            };
            let candidate = Handler {
                signature: text[..arrow + 1].to_owned(),
            };
            handlers
                .entry(name.to_owned())
                .and_modify(|existing| {
                    if guarded(&candidate.signature) {
                        *existing = Handler {
                            signature: candidate.signature.clone(),
                        };
                    }
                })
                .or_insert(candidate);
        }
    }
    handlers
}

fn guarded(signature: &str) -> bool {
    WRITE_GUARDS.iter().any(|guard| signature.contains(guard))
}

#[test]
fn route_table_parses_into_resolvable_handlers() {
    let endpoints = endpoints();
    let handlers = handlers();

    // 解析器静默失效会让整个测试变成空转，因此先锁定一个下界。
    assert!(
        endpoints.len() >= 60,
        "route parser found only {} endpoints; the parser is likely broken",
        endpoints.len()
    );
    for endpoint in &endpoints {
        assert!(
            handlers.contains_key(&endpoint.handler),
            "handler `{}` for {} {} was not found as a top-level async function",
            endpoint.handler,
            endpoint.method.to_uppercase(),
            endpoint.path
        );
    }
}

#[test]
fn state_changing_routes_enforce_csrf_or_are_explicitly_exempt() {
    let handlers = handlers();
    let mut checked = 0_usize;

    for endpoint in endpoints() {
        if !STATE_CHANGING.contains(&endpoint.method.as_str()) {
            continue;
        }
        checked += 1;
        let handler = handlers
            .get(&endpoint.handler)
            .expect("handler resolved by route_table_parses_into_resolvable_handlers");
        if guarded(&handler.signature) {
            continue;
        }
        exemption(&endpoint.path, &endpoint.method).unwrap_or_else(|| {
            panic!(
                "{} {} changes state through `{}` without SessionWrite/AdminWrite \
                 and is not in the CSRF exemption allowlist. Add the extractor, \
                 or add an entry with a documented reason.",
                endpoint.method.to_uppercase(),
                endpoint.path,
                endpoint.handler
            )
        });
    }

    assert!(
        checked >= 40,
        "only {checked} state-changing endpoints were checked; the parser is likely broken"
    );
}

#[test]
fn read_routes_do_not_require_write_guards() {
    // 读端点挂上写提取器会要求浏览器为 GET 附带 CSRF 头部，前端不会这么做，
    // 表现为登录后页面数据全部 400。这条断言把它挡在 CI。
    let handlers = handlers();
    for endpoint in endpoints() {
        if STATE_CHANGING.contains(&endpoint.method.as_str()) {
            continue;
        }
        let handler = handlers
            .get(&endpoint.handler)
            .expect("handler resolved by route_table_parses_into_resolvable_handlers");
        assert!(
            !guarded(&handler.signature),
            "{} {} is a read endpoint but `{}` requires a write guard",
            endpoint.method.to_uppercase(),
            endpoint.path,
            endpoint.handler
        );
    }
}

#[test]
fn every_exemption_maps_to_a_real_state_changing_route() {
    let endpoints = endpoints();
    for (path, method, _) in EXEMPTIONS.iter().chain(PRE_AUTH_START.iter()) {
        assert!(
            endpoints
                .iter()
                .any(|endpoint| endpoint.path == *path && endpoint.method == *method),
            "CSRF exemption for {} {path} does not match any route; remove the stale entry",
            method.to_uppercase()
        );
        assert!(
            STATE_CHANGING.contains(method),
            "CSRF exemption for {} {path} is not a state-changing method",
            method.to_uppercase()
        );
    }
}

#[test]
fn exemptions_never_shadow_write_guarded_handlers() {
    let handlers = handlers();
    for endpoint in endpoints() {
        let Some(reason) = exemption(&endpoint.path, &endpoint.method) else {
            continue;
        };
        let handler = handlers
            .get(&endpoint.handler)
            .expect("handler resolved by route_table_parses_into_resolvable_handlers");
        assert!(
            !guarded(&handler.signature),
            "{} {} is exempted as {:?}, but `{}` already uses SessionWrite/AdminWrite; \
             remove the stale exemption",
            endpoint.method.to_uppercase(),
            endpoint.path,
            reason,
            endpoint.handler
        );
    }
}

#[test]
fn csrf_validation_stays_inside_the_auth_boundary() {
    // `user_csrf_valid` 是双提交校验的唯一实现，调用点必须限定在鉴权边界内，
    // 否则又会出现「handler 自己判断要不要校验」的旧模式。
    let mut files = Vec::new();
    sources(Path::new("src"), &mut files);
    let call_sites = files
        .iter()
        .filter(|source| source.contains("user_csrf_valid("))
        .count();
    assert!(
        call_sites <= 3,
        "user_csrf_valid() is called from {call_sites} files; keep it inside \
         ui_auth, api::extract and admin::authorization"
    );
}
