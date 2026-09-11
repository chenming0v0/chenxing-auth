//! 服务端到服务端业务集成。
//!
//! 与 [`crate::oauth::providers`]（标准 OAuth 适配器）的边界：OAuth 适配器走
//! 授权码流程、邮箱验证和自动建号；本目录的集成是 service_account 模式——
//! 业务平台以服务凭据直接绑定既有辰星账号，不涉及授权码、邮箱验证或自动建号。
//! 卡密类凭据只经 adapter 转发供应商 verify，请求结束即丢弃，永不落库。

pub mod cltermux;
