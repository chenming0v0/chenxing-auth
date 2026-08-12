//! 运行时数据库角色的置备。
//!
//! ## 运行时口令为什么不能无条件重写（Issue #281）
//!
//! `configure_runtime_role` 过去每次 migrate 都执行 `ALTER ROLE ... PASSWORD`。
//! 运维在数据库侧独立轮换过该口令时，下一次 migrate 会静默把它覆盖回旧值——
//! 一次例行迁移就能把线上应用的数据库凭据打回去，而日志里看不出发生过覆盖。
//!
//! 现在先用运行时 URL 自己去登录探测一次：口令已经可用就完全不碰角色，只有登录
//! 不被接受（或角色刚被创建，本来就还没有口令）才写入，并且写入时打 warn。口令
//! 完全由外部密钥托管管理的部署可以用 `MIGRATION_MANAGE_RUNTIME_PASSWORD=false`
//! 让 migrate 一步都不碰。
//!
//! URL crate 返回的是仍带百分号编码的口令组件，而 sqlx 建连前会把它解码。写入角色
//! 时必须做同样的解码，否则含 `%40`、UTF-8 转义等内容的 URL 永远无法用刚写入的
//! 角色口令连接（Issue #309）。
//!
//! 审计表的权限边界校验在 [`super::audit_boundary`]。

use std::time::Duration;

use crate::sqlx::{Connection, PgConnection};

use super::{DbError, RUNTIME_DATABASE_ROLE};

/// migrate 对运行时角色口令的管理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePasswordPolicy {
    /// 由 migrate 保证运行时 URL 里的口令可用（探测失败才写入）。
    Managed,
    /// migrate 完全不碰口令：角色与口令由外部密钥托管或运维流程负责。
    Unmanaged,
}

/// 用运行时 URL 登录一次的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordProbe {
    /// 运行时 URL 里的口令已经能登录，不需要改动。
    Accepted,
    /// 登录未被接受（口令不对、角色刚创建还没口令，或库暂时连不上）。
    NotAccepted,
}

/// 对运行时角色口令要做的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAction {
    /// 不碰口令。
    Skip,
    /// 口令已验证可用，不碰。
    Keep,
    /// 写入运行时 URL 里的口令。
    Write,
}

/// 登录探测的超时。
///
/// 探测只是一次 TCP + 认证握手，正常在毫秒级完成。5s 足以覆盖容器冷启动，
/// 又不会让 migrate 在网络不可达时长时间挂住。超时按 `NotAccepted` 处理，
/// 退回历史行为（写入口令），不引入新的失败模式。
const PASSWORD_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// 置备固定的运行时角色。
///
/// 审计表 owner 留在迁移角色手上，运行时角色只拿到显式 GRANT 的权限。
/// 口令处理见模块文档：默认探测优先，不无条件覆盖运维侧轮换。
pub async fn configure_runtime_role(
    database: &super::Database,
    runtime_database_url: &str,
    policy: RuntimePasswordPolicy,
) -> Result<(), DbError> {
    let role_existed: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(RUNTIME_DATABASE_ROLE)
            .fetch_one(database)
            .await?;
    if !role_existed {
        crate::sqlx::query(&format!(
            "CREATE ROLE {} LOGIN",
            quote_ident(RUNTIME_DATABASE_ROLE)
        ))
        .execute(database)
        .await?;
    }

    // 只有角色本来就存在且由 migrate 管理口令时才值得探测：刚创建的角色必然
    // 还没有可用口令，探测纯属浪费一次握手。
    let probe = match (policy, role_existed) {
        (RuntimePasswordPolicy::Managed, true) => Some(probe_password(runtime_database_url).await),
        _ => None,
    };

    match runtime_password_action(policy, role_existed, probe) {
        PasswordAction::Skip => {
            if !role_existed {
                tracing::warn!(
                    role = RUNTIME_DATABASE_ROLE,
                    "created the runtime database role without a password because \
                     MIGRATION_MANAGE_RUNTIME_PASSWORD=false; provision its credential \
                     externally before starting the application"
                );
            }
        }
        PasswordAction::Keep => {
            tracing::info!(
                role = RUNTIME_DATABASE_ROLE,
                "runtime database role password already accepted; leaving it unchanged"
            );
        }
        PasswordAction::Write => {
            write_password(database, runtime_database_url).await?;
            if role_existed {
                tracing::warn!(
                    role = RUNTIME_DATABASE_ROLE,
                    "runtime database role rejected the password carried by DATABASE_URL; \
                     it has been reset to that value. If the credential was rotated on the \
                     database side, update DATABASE_URL or set \
                     MIGRATION_MANAGE_RUNTIME_PASSWORD=false"
                );
            }
        }
    }
    Ok(())
}

/// 口令动作的纯函数判定，方便在没有数据库的情况下单测。
pub(crate) fn runtime_password_action(
    policy: RuntimePasswordPolicy,
    role_existed: bool,
    probe: Option<PasswordProbe>,
) -> PasswordAction {
    match policy {
        RuntimePasswordPolicy::Unmanaged => PasswordAction::Skip,
        RuntimePasswordPolicy::Managed => match (role_existed, probe) {
            (false, _) => PasswordAction::Write,
            (true, Some(PasswordProbe::Accepted)) => PasswordAction::Keep,
            // 探测缺失或被拒都写入：宁可重设一次可恢复的口令，也不要让应用
            // 因为登录不上而起不来。重设会打 warn，运维能看到。
            (true, _) => PasswordAction::Write,
        },
    }
}

/// 把运行时 URL 携带的口令写到角色上。口令只在这一处离开 URL。
async fn write_password(
    database: &super::Database,
    runtime_database_url: &str,
) -> Result<(), DbError> {
    let password = decode_runtime_password(runtime_database_url)?;
    crate::sqlx::query(&format!(
        "ALTER ROLE {} WITH LOGIN PASSWORD {}",
        quote_ident(RUNTIME_DATABASE_ROLE),
        quote_literal(&password)
    ))
    .execute(database)
    .await?;
    Ok(())
}

/// 取出 sqlx 建连时实际使用的口令，而不是 URL 中仍带百分号编码的表示。
///
/// `percent_decode_str` 对不完整或非十六进制的 `%` 序列会原样保留，因此先按字节严格
/// 验证编码。解码完成后再整体校验 UTF-8，既能正确拼回跨多个 `%XX` 的多字节字符，
/// 也不会在原始字符串的字符边界上切片。所有失败都折叠成不携带 URL 的静态错误。
fn decode_runtime_password(runtime_database_url: &str) -> Result<String, DbError> {
    let url =
        url::Url::parse(runtime_database_url).map_err(|_| DbError::InvalidRuntimeDatabaseUrl)?;
    let encoded_password = url
        .password()
        .filter(|password| !password.is_empty())
        .ok_or(DbError::MissingRuntimeDatabasePassword)?;

    if !has_valid_percent_encoding(encoded_password.as_bytes()) {
        return Err(DbError::InvalidRuntimeDatabaseUrl);
    }

    percent_encoding::percent_decode_str(encoded_password)
        .decode_utf8()
        .map(|password| password.into_owned())
        .map_err(|_| DbError::InvalidRuntimeDatabaseUrl)
}

fn has_valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= value.len()
            || !value[index + 1].is_ascii_hexdigit()
            || !value[index + 2].is_ascii_hexdigit()
        {
            return false;
        }
        index += 3;
    }
    true
}

/// 用运行时 URL 真正登录一次，判断口令是否已经可用。
async fn probe_password(runtime_database_url: &str) -> PasswordProbe {
    let attempt = tokio::time::timeout(
        PASSWORD_PROBE_TIMEOUT,
        PgConnection::connect(runtime_database_url),
    )
    .await;
    match attempt {
        Ok(Ok(connection)) => {
            // 探测连接立刻归还，不留在服务端占额度。关闭失败无关判定结果。
            let _ = connection.close().await;
            PasswordProbe::Accepted
        }
        // 认证被拒、TLS 失败、连不上、超时都归为"不能确认口令可用"。
        Ok(Err(_)) | Err(_) => PasswordProbe::NotAccepted,
    }
}

pub(crate) fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

pub(crate) fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
#[path = "db_roles_tests.rs"]
mod tests;
