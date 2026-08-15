mod auth_audit;
pub mod avatar_handlers;
pub mod avatar_image;
pub mod credentials;
pub mod domain;
/// 邮箱规范化的唯一入口（Issue #302）。所有写路径与登录匹配都必须经过它。
pub mod email;
mod email_policy;
pub mod entitlements_handlers;
pub mod handlers;
pub mod oauth_client_handlers;
pub mod query_repository;
pub mod repository;
pub mod security_event_handlers;
pub mod service;
pub mod ui_auth;
pub mod ui_handlers;
