//! `migrate` 子命令的角色配置：谁跑迁移、谁跑运行时、审计隔离策略。
//!
//! 拆成独立模块的原因是这里全是启动期决策，可以在没有数据库的情况下完整单测；
//! 真正需要数据库的权限校验在 [`super::audit_boundary`]。
//!
//! ## 三个环境变量
//!
//! - `MIGRATION_DATABASE_URL`：迁移/owner 连接。缺失时回落到 `DATABASE_URL`，
//!   此时迁移角色与运行时角色是同一个，迁移 0019 的 REVOKE 不产生任何效果。
//! - `AUDIT_ROLE_SEPARATION`：`require`（默认）或 `allow-single-role`。默认值让
//!   上面那种降级部署直接失败，而不是静默继续（Issue #281）。
//! - `MIGRATION_MANAGE_RUNTIME_PASSWORD`：默认 `true`。设为 `false` 时 migrate
//!   不碰运行时角色口令，交给外部密钥托管。

use super::audit_boundary::AuditRoleSeparation;
use super::roles::RuntimePasswordPolicy;

pub const MIGRATION_DATABASE_URL_ENV: &str = "MIGRATION_DATABASE_URL";
pub const AUDIT_ROLE_SEPARATION_ENV: &str = "AUDIT_ROLE_SEPARATION";
pub const MANAGE_RUNTIME_PASSWORD_ENV: &str = "MIGRATION_MANAGE_RUNTIME_PASSWORD";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationPlanError {
    #[error("DATABASE_URL must be a valid PostgreSQL URL that carries a role name")]
    MissingRuntimeRole,
    #[error("MIGRATION_DATABASE_URL must be a valid PostgreSQL URL that carries a role name")]
    MissingMigrationRole,
    #[error(
        "DATABASE_URL must use the {expected} role when MIGRATION_DATABASE_URL is set, because \
         migration 0019 grants and revokes audit privileges for that exact role"
    )]
    UnexpectedRuntimeRole { expected: &'static str },
    #[error(
        "MIGRATION_DATABASE_URL is not configured, so migrations and the application would share \
         one database role. Migration 0019's REVOKE on the audit tables has no effect against the \
         table owner, which leaves the audit append-only guarantee to the trigger alone. Set \
         MIGRATION_DATABASE_URL to the owner role and keep DATABASE_URL on the runtime role, or \
         set {env}=allow-single-role to accept a trigger-only audit boundary"
    )]
    SingleRoleNotAllowed { env: &'static str },
    #[error("{env} must be either require or allow-single-role")]
    InvalidSeparationPolicy { env: &'static str },
    #[error("{env} must be a boolean value")]
    InvalidPasswordPolicy { env: &'static str },
}

/// `migrate` 子命令解析出的角色配置。
#[derive(Clone)]
pub struct MigrationPlan {
    migration_database_url: String,
    runtime_database_url: String,
    migration_role: String,
    runtime_role: String,
    roles_separated: bool,
    separation: AuditRoleSeparation,
    password_policy: RuntimePasswordPolicy,
}

// URL 带口令，绝不能进日志或错误链。角色名本身不是凭据，保留它才能定位问题。
impl std::fmt::Debug for MigrationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationPlan")
            .field("migration_database_url", &"<redacted>")
            .field("runtime_database_url", &"<redacted>")
            .field("migration_role", &self.migration_role)
            .field("runtime_role", &self.runtime_role)
            .field("roles_separated", &self.roles_separated)
            .field("separation", &self.separation)
            .field("password_policy", &self.password_policy)
            .finish()
    }
}

impl MigrationPlan {
    /// 从环境变量构造。`runtime_database_url` 来自已解析的 `Config`，
    /// 因此这里只读 migrate 专属的三个变量。
    pub fn from_env(runtime_database_url: &str) -> Result<Self, MigrationPlanError> {
        Self::from_values(
            runtime_database_url,
            std::env::var(MIGRATION_DATABASE_URL_ENV).ok().as_deref(),
            std::env::var(AUDIT_ROLE_SEPARATION_ENV).ok().as_deref(),
            std::env::var(MANAGE_RUNTIME_PASSWORD_ENV).ok().as_deref(),
        )
    }

    /// 纯函数构造，供单测直接注入取值。空白取值等同未设置。
    pub fn from_values(
        runtime_database_url: &str,
        migration_database_url: Option<&str>,
        separation: Option<&str>,
        manage_runtime_password: Option<&str>,
    ) -> Result<Self, MigrationPlanError> {
        let migration_database_url = migration_database_url
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let separation = parse_separation(separation)?;
        let password_policy = parse_password_policy(manage_runtime_password)?;

        let runtime_role =
            role_of(runtime_database_url).ok_or(MigrationPlanError::MissingRuntimeRole)?;
        let migration_role = match migration_database_url {
            Some(url) => role_of(url).ok_or(MigrationPlanError::MissingMigrationRole)?,
            None => runtime_role.clone(),
        };

        // 判据是角色是否真的不同，而不是变量有没有设置：把
        // MIGRATION_DATABASE_URL 显式设成与 DATABASE_URL 同一个角色，边界一样不成立。
        let roles_separated = migration_role != runtime_role;
        if roles_separated {
            if runtime_role != super::RUNTIME_DATABASE_ROLE {
                return Err(MigrationPlanError::UnexpectedRuntimeRole {
                    expected: super::RUNTIME_DATABASE_ROLE,
                });
            }
        } else if separation == AuditRoleSeparation::Require {
            return Err(MigrationPlanError::SingleRoleNotAllowed {
                env: AUDIT_ROLE_SEPARATION_ENV,
            });
        }

        Ok(Self {
            migration_database_url: migration_database_url
                .unwrap_or(runtime_database_url)
                .to_owned(),
            runtime_database_url: runtime_database_url.to_owned(),
            migration_role,
            runtime_role,
            roles_separated,
            separation,
            // 单角色部署里"运行时角色"就是 owner，chenxing_runtime 不参与运行，
            // 给它设口令没有意义，只会平白多一个可登录凭据。
            password_policy: if roles_separated {
                password_policy
            } else {
                RuntimePasswordPolicy::Unmanaged
            },
        })
    }

    pub fn migration_database_url(&self) -> &str {
        &self.migration_database_url
    }

    pub fn runtime_database_url(&self) -> &str {
        &self.runtime_database_url
    }

    pub fn runtime_role(&self) -> &str {
        &self.runtime_role
    }

    pub fn roles_separated(&self) -> bool {
        self.roles_separated
    }

    pub fn separation(&self) -> AuditRoleSeparation {
        self.separation
    }

    pub fn password_policy(&self) -> RuntimePasswordPolicy {
        self.password_policy
    }

    /// 在迁移开始前把当前的角色姿态写进日志。
    ///
    /// 单角色部署走到这里说明运维已经显式设过 `allow-single-role`，
    /// 但它仍然是生产不可接受的配置，所以每次都强告警而不是只说一次。
    pub fn log_posture(&self) {
        if self.roles_separated {
            tracing::info!(
                migration_role = %self.migration_role,
                runtime_role = %self.runtime_role,
                "running migrations with a separate owner role; the runtime role stays \
                 restricted on the audit tables"
            );
        } else {
            tracing::warn!(
                role = %self.runtime_role,
                policy = self.separation.as_str(),
                env = MIGRATION_DATABASE_URL_ENV,
                "MIGRATIONS AND THE APPLICATION SHARE ONE DATABASE ROLE: that role owns the \
                 audit tables, so migration 0019's REVOKE cannot restrict it and audit \
                 append-only is enforced by the trigger alone. This is not a supported \
                 production posture"
            );
        }
    }
}

fn parse_separation(value: Option<&str>) -> Result<AuditRoleSeparation, MigrationPlanError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(AuditRoleSeparation::Require);
    };
    match value.to_ascii_lowercase().as_str() {
        "require" => Ok(AuditRoleSeparation::Require),
        "allow-single-role" => Ok(AuditRoleSeparation::AllowSingleRole),
        _ => Err(MigrationPlanError::InvalidSeparationPolicy {
            env: AUDIT_ROLE_SEPARATION_ENV,
        }),
    }
}

fn parse_password_policy(value: Option<&str>) -> Result<RuntimePasswordPolicy, MigrationPlanError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(RuntimePasswordPolicy::Managed);
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(RuntimePasswordPolicy::Managed),
        "false" | "0" | "no" => Ok(RuntimePasswordPolicy::Unmanaged),
        _ => Err(MigrationPlanError::InvalidPasswordPolicy {
            env: MANAGE_RUNTIME_PASSWORD_ENV,
        }),
    }
}

/// 取 URL 里的角色名。URL 非法或没有用户名都视为缺失。
fn role_of(database_url: &str) -> Option<String> {
    let url = url::Url::parse(database_url).ok()?;
    let username = url.username();
    (!username.is_empty()).then(|| username.to_owned())
}

#[cfg(test)]
#[path = "db_migrate_tests.rs"]
mod tests;
