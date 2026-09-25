//! Android App Links 声明的持久化：按 Client 档案行整体增删。

use std::collections::HashMap;

use crate::clients::android_link::AndroidAssetLink;
use crate::sqlx::PgPool;
use serde_json::Value;

pub struct DeclaredAppLinkRow {
    pub client_id: String,
    pub numeric_app_id: i64,
    pub client_name: String,
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

/// 用已校验的声明覆盖一个 Client 的 App Link。
///
/// 这是 Owner 显式操作；不存在跨 Client 的包名所有权仲裁（同一域名下
/// 多个官方 Client 可以共享包名——同一 App 可以有多个 Client 实例）。
/// 会话复核、行更新和审计在同一个事务里，复核失败或审计失败都不会留下声明。
pub async fn upsert_client_app_link(
    pool: &PgPool,
    client_id: &str,
    link: &AndroidAssetLink,
    management_actor: crate::users::ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, super::AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        Some(management_actor),
        crate::users::domain::UserPermission::ManageIssuer,
    )
    .await?;
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET android_asset_link = $2
         WHERE client_id = $1",
    )
    .bind(client_id)
    .bind(serde_json::to_value(link).expect("asset link is serializable"))
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
    transaction.commit().await?;
    Ok(true)
}

/// 清空一个 Client 档案上的 App Link 声明。
///
/// 与写入一样，复核、清空和审计共享一个事务。
pub async fn delete_client_app_link(
    pool: &PgPool,
    client_id: &str,
    management_actor: crate::users::ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<bool, super::AuditedClientMutationError> {
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        Some(management_actor),
        crate::users::domain::UserPermission::ManageIssuer,
    )
    .await?;
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET android_asset_link = NULL
         WHERE client_id = $1",
    )
    .bind(client_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
    transaction.commit().await?;
    Ok(true)
}

/// 管理面：每个已发布 Client 一行，按数字 App ID 排序。
pub async fn list_declared_app_links(
    pool: &PgPool,
) -> Result<Vec<DeclaredAppLinkRow>, crate::sqlx::Error> {
    let rows: Vec<(String, i64, String, Option<Value>)> = crate::sqlx::query_as(
        "SELECT client_id, numeric_app_id, client_name, android_asset_link FROM oauth_clients
         WHERE android_asset_link IS NOT NULL
         ORDER BY numeric_app_id ASC, id ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(client_id, numeric_app_id, client_name, value)| {
            match value.and_then(|value| serde_json::from_value::<AndroidAssetLink>(value).ok()) {
                Some(link) => Some(DeclaredAppLinkRow {
                    client_id,
                    numeric_app_id,
                    client_name,
                    package_name: link.package_name,
                    sha256_cert_fingerprints: link.sha256_cert_fingerprints,
                }),
                None => {
                    tracing::error!(
                        client_id,
                        "oauth_clients.android_asset_link failed to deserialize"
                    );
                    None
                }
            }
        })
        .collect())
}

/// 公开读取：发布 Owner 已登记的声明。同包名指纹合并，顺序按该包名首次出现的 Client。
pub async fn list_client_app_links(
    pool: &PgPool,
) -> Result<Vec<(String, Vec<String>)>, crate::sqlx::Error> {
    let rows: Vec<(Option<Value>,)> = crate::sqlx::query_as(
        "SELECT android_asset_link FROM oauth_clients
         WHERE android_asset_link IS NOT NULL
         ORDER BY numeric_app_id ASC, id ASC",
    )
    .fetch_all(pool)
    .await?;
    let mut by_package: Vec<(String, Vec<String>)> = Vec::new();
    let mut index = HashMap::<String, usize>::new();
    for (value,) in rows {
        let Some(value) = value else {
            continue;
        };
        let Ok(link) = serde_json::from_value::<AndroidAssetLink>(value) else {
            tracing::error!("oauth_clients.android_asset_link failed to deserialize");
            continue;
        };
        let slot = *index.entry(link.package_name.clone()).or_insert_with(|| {
            let slot = by_package.len();
            by_package.push((link.package_name.clone(), Vec::new()));
            slot
        });
        for fingerprint in link.sha256_cert_fingerprints {
            if !by_package[slot].1.contains(&fingerprint) {
                by_package[slot].1.push(fingerprint);
            }
        }
    }
    Ok(by_package)
}

/// 公开读取：按数字 App ID 取 active Client 的 Android 声明。
///
/// 没有行，或 `android_asset_link` 为 NULL，都是「未发布」。JSON 无法解码是
/// 存储错误，调用方应返回 503，而不是把它伪装成未发布。
pub async fn find_active_client_app_link(
    pool: &PgPool,
    numeric_app_id: i64,
) -> Result<Option<AndroidAssetLink>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, (Option<crate::sqlx::types::Json<AndroidAssetLink>>,)>(
        "SELECT android_asset_link FROM oauth_clients
         WHERE numeric_app_id = $1 AND status = 'active'",
    )
    .bind(numeric_app_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(link,)| link.map(|link| link.0)))
}
