//! 迁移后复核 `users.canonical_email`（Issue #302 / #461）。
//!
//! PostgreSQL 可以强制该列非空且唯一，却不能在不复制 UTS-46 的前提下证明它与
//! 展示邮箱一致。SQL 再聪明也只能猜：筛 `xn--` 会漏掉 Unicode 域名、错误的纯
//! ASCII 匹配值，以及只差本地部分大小写的行。因此显式 migrate 命令用唯一的权威
//! 实现 [`EmailAddress`] 扫完全表。
//!
//! 不一致时**拒绝启动**。匹配值一旦落错，登录会静默失败，而错误看起来像
//! "密码不对"——放行是把一个可诊断的启动故障换成一个查不出原因的线上故障。

use crate::users::email::EmailAddress;

use super::Database;

/// 每批从主键游标往后取的行数。
///
/// 必须扫完全表，又不能 `fetch_all` 整张用户表：一次加载会把迁移峰值内存绑死在
/// 用户规模上。按 `id` 键集分页，工作集是当前批加上不一致的 id 列表。
const VERIFY_BATCH_SIZE: i64 = 500;

pub(super) async fn verify(database: &Database) -> Result<(), crate::sqlx::migrate::MigrateError> {
    let mut last_id = 0_i64;
    let mut offending = Vec::new();

    loop {
        let rows: Vec<(i64, String, String)> = crate::sqlx::query_as(
            "SELECT id, email, canonical_email FROM users
             WHERE id > $1
             ORDER BY id
             LIMIT $2",
        )
        .bind(last_id)
        .bind(VERIFY_BATCH_SIZE)
        .fetch_all(database)
        .await?;

        let Some(next_id) = rows.last().map(|(id, _, _)| *id) else {
            break;
        };
        last_id = next_id;

        offending.extend(
            rows.into_iter()
                .filter(|(_, email, stored)| !canonical_email_matches(email, stored))
                .map(|(id, _, _)| id),
        );
    }

    if offending.is_empty() {
        return Ok(());
    }

    // 只报 id，不报地址本身：这条消息会进启动日志，而地址是个人数据。
    tracing::error!(
        user_ids = ?offending,
        "users.canonical_email disagrees with the application canonicalizer; refusing to start"
    );
    Err(crate::sqlx::migrate::MigrateError::Execute(
        crate::sqlx::Error::Protocol(format!(
            "canonical_email mismatch for {} user row(s): id in {:?}. \
             These rows store a matching value that differs from what the \
             application EmailAddress parser computes, so their owners cannot log in. \
             Fix users.email and canonical_email for each id, then restart. \
             The canonical value must come from the application EmailAddress parser.",
            offending.len(),
            offending,
        )),
    ))
}

/// 展示值经应用层规范化后是否与库存匹配值逐字节相同。
///
/// 解析失败也算不一致：库存行已经存在，权威实现却认不出它，登录路径同样走不通。
fn canonical_email_matches(email: &str, stored: &str) -> bool {
    EmailAddress::parse(email).is_ok_and(|parsed| parsed.canonical() == stored)
}

#[cfg(test)]
#[path = "canonical_email_tests.rs"]
mod tests;
