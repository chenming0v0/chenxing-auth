//! 套餐 / 权益领域边界：把 OAuth 客户端数量、日/月授权配额和并发 QPS
//! 从硬编码常量迁移为管理员可配置的套餐，并为用户挂载套餐。

pub mod domain;
pub mod repository;
mod row;
pub mod service;
