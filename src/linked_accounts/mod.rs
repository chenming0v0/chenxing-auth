//! 用户视角的"已连接账号"领域模块（Issue #706）。
//!
//! 协议里 linked-accounts 是聚合资源：OAuth 外部身份（`oauth_external_identities`，
//! 由 `src/oauth/providers/` 负责）与业务服务绑定（`linked_accounts` 表，本模块
//! 负责的仓储层）在 service 层合并成一个用户视角的列表。本模块只承载新表的
//! 持久化边界；聚合逻辑由下游 service lane 在 service 层完成，不落在仓储里。
//!
//! 表结构由迁移 0053 定义。两条唯一约束（provider+uid、provider+user）是并发
//! 一致性的权威来源：仓储层靠唯一冲突的约束名区分"同一用户重复提交同一 uid"
//! 与"uid 被他人占用"，不做 check-then-insert。

mod error;
pub mod exchange;
pub mod handlers;
mod pagination;
mod provider;
pub mod repository;
mod response;
pub mod service;
mod views;

pub use error::LinkedAccountServiceError;
pub use repository::{LinkedAccountRepository, LinkedAccountRow, StoreBindingError};
pub use service::{LinkedAccountService, LinkedAccountView};
