//! 审计 append-only 权限边界的启动期校验。
//!
//! ## 边界为什么必须在启动期校验（Issue #281）
//!
//! 当前数据库基线把审计 append-only 从"触发器"升级为"PostgreSQL 权限"，做法是让
//! 迁移角色持有审计表 owner，再对 `chenxing_runtime` 执行
//! `REVOKE UPDATE, DELETE, TRUNCATE`（热表）以及归档表上的 `INSERT`。这条边界只在
//! "运行时角色 ≠ 表 owner"时成立：
//! owner 在 PostgreSQL 里隐含全部表权限，REVOKE 对自己无效。
//!
//! 因此未配置 `MIGRATION_DATABASE_URL` 的部署（迁移与运行时共用同一角色）里，
//! 基线的 REVOKE 一行都没生效，审计边界退回只剩触发器一层——而触发器的归档
//! 旁路标记是会话级 GUC，任何能连库的会话都能设置。这种降级过去是静默的：
//! migrate 正常成功，日志里看不出边界已经不存在。
//!
//! ## 必须问有效主体，不能问 URL 用户名（Issue #649）
//!
//! `has_table_privilege(role, table, privilege)` 的 `role` 参数是调用方提供的
//! 名字。把 `DATABASE_URL` 用户名塞进去，检查的是那个名字在目录里的权限，不是
//! 这条连接上真正执行 SQL 的角色。代理、`SET ROLE`、连接 `options` 都可以让
//! `current_user` 变成 owner，同时 URL 仍然写着 `chenxing_runtime`。目录检查会
//! 通过，应用却能改 append-only 审计数据。
//!
//! 这里在**同一条**池连接上读取 `current_user` / `session_user`，并用两参数形式
//! 的 `has_table_privilege`（对应当前有效主体）。URL 用户名只用来比对声称的
//! 角色；对不上就按策略拒绝。热表 DELETE 和归档 INSERT 都算 mutability。

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
    /// 必须为 false：热表或归档表上的 UPDATE/DELETE/TRUNCATE，以及归档表上的
    /// INSERT，任意一个存在，append-only 边界就不成立。
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
        "runtime database role {role} can still mutate the audit tables (UPDATE/DELETE/TRUNCATE, \
         or INSERT on the archive), so the append-only boundary from the current baseline is not \
         in effect. Configure MIGRATION_DATABASE_URL with the owner role and keep DATABASE_URL on \
         {expected_role}, or set AUDIT_ROLE_SEPARATION=allow-single-role to accept a trigger-only \
         audit boundary"
    )]
    RuntimeRoleCanMutateAudit {
        role: String,
        expected_role: &'static str,
    },
    #[error(
        "the database connection is executing as {current_user} (session_user={session_user}), \
         not the configured runtime role {expected_role}. A proxy, SET ROLE, or connection option \
         is substituting a different principal, so privilege checks against the URL username \
         would not describe this process. Connect as {expected_role} without role switching, or \
         set AUDIT_ROLE_SEPARATION=allow-single-role to accept a trigger-only audit boundary"
    )]
    EffectiveRoleMismatch {
        current_user: String,
        session_user: String,
        expected_role: String,
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

/// 一条连接、一次往返：身份和权限位必须来自同一个会话。拆成多次 checkout
/// 会让 `SET ROLE` 之后的池连接互相交错（Issue #649）。
///
/// 表名和函数名按 `search_path` 解析，与应用使用非限定名的方式一致，
/// 因此 per-test schema 隔离下也会检查该 schema 里的对象。
const AUDIT_PRIVILEGE_SQL: &str = "\
SELECT current_user::text, \
       session_user::text, \
       has_table_privilege('audit_events', 'INSERT'), \
       has_table_privilege('audit_events', 'SELECT') \
         AND has_table_privilege('audit_events_archive', 'SELECT'), \
       has_function_privilege('archive_audit_events(integer,integer)', 'EXECUTE'), \
       has_table_privilege('audit_events', 'UPDATE') \
         OR has_table_privilege('audit_events', 'DELETE') \
         OR has_table_privilege('audit_events', 'TRUNCATE') \
         OR has_table_privilege('audit_events_archive', 'UPDATE') \
         OR has_table_privilege('audit_events_archive', 'DELETE') \
         OR has_table_privilege('audit_events_archive', 'TRUNCATE') \
         OR has_table_privilege('audit_events_archive', 'INSERT')";

/// 校验运行时角色在审计表上的权限隔离，失败时按策略拒绝。
///
/// 必须在迁移之后、应用启动之前执行：它读的是这条连接上此刻的有效主体，
/// 而不是 `DATABASE_URL` 里写的用户名，也不是迁移文件里写了什么。
pub async fn verify_audit_append_only_boundary(
    database: &super::Database,
    runtime_role: &str,
    separation: AuditRoleSeparation,
) -> Result<AuditPrivileges, AuditBoundaryError> {
    let snapshot = audit_privilege_snapshot(database).await?;
    let privileges = snapshot.privileges;
    let matched = principal_matches(&snapshot.current_user, &snapshot.session_user, runtime_role);

    if !matched && separation == AuditRoleSeparation::Require {
        return Err(AuditBoundaryError::EffectiveRoleMismatch {
            current_user: snapshot.current_user,
            session_user: snapshot.session_user,
            expected_role: runtime_role.to_owned(),
        });
    }

    if !(privileges.can_insert && privileges.can_select && privileges.can_archive) {
        return Err(AuditBoundaryError::MissingRuntimePrivilege {
            role: snapshot.current_user,
            can_insert: privileges.can_insert,
            can_select: privileges.can_select,
            can_archive: privileges.can_archive,
        });
    }

    match audit_boundary_verdict(privileges, matched, separation) {
        AuditBoundaryVerdict::Enforced => {
            tracing::info!(
                current_user = %snapshot.current_user,
                session_user = %snapshot.session_user,
                "audit append-only boundary verified: the runtime role cannot mutate audit tables"
            );
            Ok(privileges)
        }
        AuditBoundaryVerdict::DegradedButAllowed => {
            tracing::warn!(
                current_user = %snapshot.current_user,
                session_user = %snapshot.session_user,
                expected_role = runtime_role,
                policy = separation.as_str(),
                "AUDIT APPEND-ONLY IS TRIGGER-ONLY: the effective PostgreSQL principal can \
                 mutate the audit tables, or is not the configured runtime role, so the \
                 baseline REVOKE has no effect. The archive bypass marker is a session GUC that \
                 any session holding this role can set. Do not run production this way: set \
                 MIGRATION_DATABASE_URL to the owner role and keep DATABASE_URL on the runtime role"
            );
            Ok(privileges)
        }
        AuditBoundaryVerdict::Violated => Err(AuditBoundaryError::RuntimeRoleCanMutateAudit {
            role: snapshot.current_user,
            expected_role: RUNTIME_DATABASE_ROLE,
        }),
    }
}

/// 判定的纯函数部分，便于单测覆盖策略矩阵。
///
/// `principal_matched` 为 false 表示 `current_user` / `session_user` 对不上
/// URL 声称的运行时角色：边界对这条连接不成立，即使目录里那个名字本身不能改表。
pub(crate) fn audit_boundary_verdict(
    privileges: AuditPrivileges,
    principal_matched: bool,
    separation: AuditRoleSeparation,
) -> AuditBoundaryVerdict {
    let boundary_holds = !privileges.can_mutate && principal_matched;
    match (boundary_holds, separation) {
        (true, _) => AuditBoundaryVerdict::Enforced,
        (false, AuditRoleSeparation::AllowSingleRole) => AuditBoundaryVerdict::DegradedButAllowed,
        (false, AuditRoleSeparation::Require) => AuditBoundaryVerdict::Violated,
    }
}

pub(crate) fn principal_matches(
    current_user: &str,
    session_user: &str,
    expected_role: &str,
) -> bool {
    current_user == expected_role && session_user == expected_role
}

struct AuditPrivilegeSnapshot {
    current_user: String,
    session_user: String,
    privileges: AuditPrivileges,
}

/// 读取**这条连接**上有效主体的实际权限。
///
/// 用两参数 `has_table_privilege(table, privilege)`，它绑定 `current_user`，
/// 把 owner 隐含权限、角色继承和 superuser 旁路都算进去。三参数形式如果吃的是
/// URL 用户名，会把 `SET ROLE` 之后的有效主体漏掉。
async fn audit_privilege_snapshot(
    database: &super::Database,
) -> Result<AuditPrivilegeSnapshot, crate::sqlx::Error> {
    let mut connection = database.acquire().await?;
    let (current_user, session_user, can_insert, can_select, can_archive, can_mutate): (
        String,
        String,
        bool,
        bool,
        bool,
        bool,
    ) = crate::sqlx::query_as(AUDIT_PRIVILEGE_SQL)
        .fetch_one(&mut *connection)
        .await?;
    Ok(AuditPrivilegeSnapshot {
        current_user,
        session_user,
        privileges: AuditPrivileges {
            can_insert,
            can_select,
            can_archive,
            can_mutate,
        },
    })
}

#[cfg(test)]
#[path = "audit_boundary_tests.rs"]
mod tests;
