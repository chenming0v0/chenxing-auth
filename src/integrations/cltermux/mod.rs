//! CLtermux 业务账号绑定集成（Issue #706）。
//!
//! 模块划分：
//! - [`types`]：绑定用例的领域类型，不与 HTTP 契约混合。
//! - [`contract`]：CLtermux HTTP 契约的 serde 类型（出站请求/入站响应）。
//! - [`validation`]：入站快照的结构校验与入站 token 摘要校验。
//!
//! 安全边界：卡密凭据（公钥/私钥）只在请求生命周期内存在，经 adapter 转发
//! 供应商 verify 后即丢弃，永不落库/日志/队列；入站服务凭据只存 SHA-256 摘要。

pub mod adapter;
pub mod client;
pub mod contract;
pub mod types;
pub mod validation;
