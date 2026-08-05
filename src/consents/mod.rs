//! 用户同意记录的领域、存储与用例边界（Issue #91 分层重构）。
//!
//! **结构**（跟随 `clients` 模块的 domain / repository / service 三段式）：
//! - [`domain`]：数据结构、错误类型与不依赖存储的领域规则
//! - [`repository`]：`ConsentRepository` 存储边界与 PostgreSQL 实现（唯一 SQL 出口）
//! - [`service`]：用例编排，泛型依赖存储 trait
//!
//! **对外路径兼容**：
//! 本模块由单文件 `src/consents.rs` 拆分而来，下列路径保持不变，
//! 外部调用方（`state.rs`、`oauth/ui_handlers.rs`、`users/oauth_client_handlers.rs`）
//! 无需修改 `use` 语句：
//! - `crate::consents::ConsentService`
//! - `crate::consents::ConsentServiceError`
//! - `crate::consents::AuthorizedApp`

pub mod domain;
pub mod repository;
pub mod service;

pub use domain::{AuthorizedApp, ConsentServiceError};
pub use service::ConsentService;
