//! 审计 append-only 权限边界的启动期校验。
//!
//! ## 边界为什么必须在启动期校验（Issue #281）
//!
//! 当前数据库基线把审计 append-only 从"触发器"升级为"PostgreSQL 权限"，做法是让
//! 迁移角色持有审计表 owner，再对 `chenxing_runtime` 执行
//! `REVOKE UPDATE, DELETE, TRUNCATE`。这条边界只在"运行时角色 ≠ 表 owner"时成立：
//! owner 在 PostgreSQL 里隐含全部表权限，REVOKE 对自己无效。
//!
//! 因此未配置 `MIGRATION_DATABASE_URL` 的部署（迁移与运行时共用同一角色）里，
//! 基线的 REVOKE 一行都没生效，审计边界退回只剩触发器一层——而触发器的归档
//! 旁路标记是会话级 GUC，任何能连库的会话都能设置。这种降级过去是静默的：
//! migrate 正常成功，日志里看不出边界已经不存在。
//!
//! 这里的做法是直接问数据库：`has_table_privilege(runtime_role, 'audit_events',
//! 'DELETE')`。这个函数把 owner 隐含权限、`GRANT`、角色继承和 superuser 旁路都算
//! 进去了，所以它回答的正是"运行时角色实际上能不能删审计行"，而不是"我们以为
//! 我们 REVOKE 过"。返回 true 就按策略拒绝启动或强告警，不再静默继续。

use super::RUNTIME_DATABASE_ROLE;

/// 审计角色隔离策略，来自 `AUDIT_ROLE_SEPARATION`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRoleSeparation {
    /// 生产默认：运行时角色必须真的没有审计表的修改权限，否则 migrate 失败。
    Require,
    /// 显式声明的不安全开关：允许迁移角色与运行时角色共用一个角色。
    /// 审计 append-only 此时只剩触发器一层，每次 migrate 都会强告警。
    AllowSingleRole,
}

impl AuditRoleSeparation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Require => "require",
            Self::AllowSingleRole => "allow-single-role",
        }
    }
}

/// 运行时角色在审计表上的实际权限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditPrivileges {
    /// 写审计事件所必需。
    pub can_insert: bool,
    /// 查询审计事件（含归档表）所必需。
    pub can_select: bool,
    /// 通过 `SECURITY DEFINER` 归档函数搬运过期事件所必需。
    pub can_archive: bool,
    /// 必须为 false：这三个权限任意一个存在，append-only 边界就不成立。
    pub can_mutate: bool,
}

/// 审计边界校验的判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBoundaryVerdict {
    /// 运行时角色确实无法修改审计表。
    Enforced,
    /// 边界不成立，但运维显式接受了单角色部署，只强告警。
    DegradedButAllowed,
    /// 边界不成立且策略要求隔离，必须拒绝。
    Violated,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditBoundaryError {
    #[error(
        "runtime database role {role} can still UPDATE/DELETE/TRUNCATE the audit tables, so the \
         append-only boundary from the current baseline is not in effect. Configure \
         MIGRATION_DATABASE_URL with the owner role and keep DATABASE_URL on {expected_role}, or \
         set AUDIT_ROLE_SEPARATION=allow-single-role to accept a trigger-only audit boundary"
    )]
    RuntimeRoleCanMutateAudit {
        role: String,
        expected_role: &'static str,
    },
    #[error(
        "runtime database role {role} is missing a privilege the application needs on the audit \
         tables (insert={can_insert}, select={can_select}, archive={can_archive}); re-run the \
         migrations with the owner role"
    )]
    MissingRuntimePrivilege {
        role: String,
        can_insert: bool,
        can_select: bool,
        can_archive: bool,
    },
    #[error("audit privilege verification query failed")]
    Query(#[from] crate::sqlx::Error),
}

const AUDIT_HOT_TABLE: &str = "audit_events";
const AUDIT_ARCHIVE_TABLE: &str = "audit_events_archive";
/// `regprocedure` 形式的函数签名，`has_function_privilege` 按 `search_path` 解析。
const AUDIT_ARCHIVE_FUNCTION: &str = "archive_audit_events(integer,integer)";

/// 校验运行时角色在审计表上的权限隔离，失败时按策略拒绝。
///
/// 必须在迁移之后、应用启动之前执行：它读的是数据库里此刻真实的权限，
/// 而不是迁移文件里写了什么。
pub async fn verify_audit_append_only_boundary(
    database: &super::Database,
    runtime_role: &str,
    separation: AuditRoleSeparation,
) -> Result<AuditPrivileges, AuditBoundaryError> {
    let privileges = audit_privileges(database, runtime_role).await?;

    if !(privileges.can_insert && privileges.can_select && privileges.can_archive) {
        return Err(AuditBoundaryError::MissingRuntimePrivilege {
            role: runtime_role.to_owned(),
            can_insert: privileges.can_insert,
            can_select: privileges.can_select,
            can_archive: privileges.can_archive,
        });
    }

    match audit_boundary_verdict(privileges, separation) {
        AuditBoundaryVerdict::Enforced => {
            tracing::info!(
                role = runtime_role,
                "audit append-only boundary verified: the runtime role cannot mutate audit tables"
            );
            Ok(privileges)
        }
        AuditBoundaryVerdict::DegradedButAllowed => {
            tracing::warn!(
                role = runtime_role,
                policy = separation.as_str(),
                "AUDIT APPEND-ONLY IS TRIGGER-ONLY: the runtime role owns or was granted \
                 UPDATE/DELETE/TRUNCATE on the audit tables, so the baseline REVOKE has no \
                 effect. The archive bypass marker is a session GUC that any session holding \
                 this role can set. Do not run production this way: set MIGRATION_DATABASE_URL \
                 to the owner role and keep DATABASE_URL on the runtime role"
            );
            Ok(privileges)
        }
        AuditBoundaryVerdict::Violated => Err(AuditBoundaryError::RuntimeRoleCanMutateAudit {
            role: runtime_role.to_owned(),
            expected_role: RUNTIME_DATABASE_ROLE,
        }),
    }
}

/// 判定的纯函数部分，便于单测覆盖策略矩阵。
pub(crate) fn audit_boundary_verdict(
    privileges: AuditPrivileges,
    separation: AuditRoleSeparation,
) -> AuditBoundaryVerdict {
    match (privileges.can_mutate, separation) {
        (false, _) => AuditBoundaryVerdict::Enforced,
        (true, AuditRoleSeparation::AllowSingleRole) => AuditBoundaryVerdict::DegradedButAllowed,
        (true, AuditRoleSeparation::Require) => AuditBoundaryVerdict::Violated,
    }
}

/// 读取运行时角色在审计对象上的实际权限。
///
/// 用 `has_table_privilege` 而不是读 `information_schema.table_privileges`：
/// 前者把 owner 隐含权限、角色继承和 superuser 旁路都算进去，后者只看显式
/// GRANT，会把"owner 什么都能做"这个关键情况漏掉。
async fn audit_privileges(
    database: &super::Database,
    runtime_role: &str,
) -> Result<AuditPrivileges, crate::sqlx::Error> {
    let can_insert = has_table_privilege(database, runtime_role, AUDIT_HOT_TABLE, "INSERT").await?;
    let can_select = has_table_privilege(database, runtime_role, AUDIT_HOT_TABLE, "SELECT").await?
        && has_table_privilege(database, runtime_role, AUDIT_ARCHIVE_TABLE, "SELECT").await?;
    let can_archive = has_function_privilege(database, runtime_role).await?;

    let mut can_mutate = false;
    for table in [AUDIT_HOT_TABLE, AUDIT_ARCHIVE_TABLE] {
        for privilege in ["UPDATE", "DELETE", "TRUNCATE"] {
            if has_table_privilege(database, runtime_role, table, privilege).await? {
                can_mutate = true;
            }
        }
    }

    Ok(AuditPrivileges {
        can_insert,
        can_select,
        can_archive,
        can_mutate,
    })
}

async fn has_table_privilege(
    database: &super::Database,
    role: &str,
    table: &str,
    privilege: &str,
) -> Result<bool, crate::sqlx::Error> {
    // 表名按 `search_path` 解析，与应用代码使用非限定表名的方式一致，
    // 因此 per-test schema 隔离下也会检查该 schema 里的表。
    crate::sqlx::query_scalar("SELECT has_table_privilege($1::name, $2::text, $3::text)")
        .bind(role.to_owned())
        .bind(table.to_owned())
        .bind(privilege.to_owned())
        .fetch_one(database)
        .await
}

async fn has_function_privilege(
    database: &super::Database,
    role: &str,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT has_function_privilege($1::name, $2::text, 'EXECUTE')")
        .bind(role.to_owned())
        .bind(AUDIT_ARCHIVE_FUNCTION)
        .fetch_one(database)
        .await
}

#[cfg(test)]
#[path = "db_audit_boundary_tests.rs"]
mod tests;
