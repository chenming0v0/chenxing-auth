//! 可复用的请求上下文提取，保持 api::source_ip / api::user_agent 调用路径。

use axum::http::HeaderMap;
use std::net::SocketAddr;

use crate::config::TrustedProxies;

/// 从请求对端地址和头部解析真实客户端 IP。
///
/// 未配置可信代理或对端不可信时忽略 XFF；可信对端的所有 XFF 头部按线序合并，
/// 再从右向左取第一个不可信地址，防止客户端伪造源 IP（#111 / #269）。
pub(crate) fn source_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    trusted_proxies.resolve_client_ip(peer, headers)
}

/// User-Agent 可被任意伪造；审计上下文只保留前 512 字符，非法 UTF-8 返回 None。
pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    const MAX_USER_AGENT_CHARS: usize = 512;
    let value = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    Some(match value.char_indices().nth(MAX_USER_AGENT_CHARS) {
        Some((index, _)) => value[..index].to_owned(),
        None => value.to_owned(),
    })
}
