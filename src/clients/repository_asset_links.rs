//! Android App Links 声明的持久化：按 Client 档案行整体增删。

use std::collections::HashMap;

use crate::clients::android_link::AndroidAssetLink;
use crate::sqlx::PgPool;
use crate::users::domain::UserId;
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
/// 多个 Client 可以共享包名——同一 App 可以有多个 Client 实例）。
pub async fn upsert_client_app_link(
    pool: &PgPool,
    client_id: &str,
    owner_user_id: Option<UserId>,
    link: &AndroidAssetLink,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET android_asset_link = $3
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(serde_json::to_value(link).expect("asset link is serializable"))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 清空一个 Client 的 App Link 声明（不再参与 `/.well-known/assetlinks.json`）。
pub async fn delete_client_app_link(
    pool: &PgPool,
    client_id: &str,
    owner_user_id: Option<UserId>,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET android_asset_link = NULL
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 管理面：每个已登记 Client 一行，按数字 App ID 排序。
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

/// 公开读取：同包名指纹合并，顺序按该包名首次出现的 Client。
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
