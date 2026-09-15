//! Android App Links 声明管理：公开读取 + Owner 增删。

use super::{ClientService, ClientServiceError};
use crate::clients::android_link::{
    AndroidAssetLink, AndroidAssetLinkInput, validate_android_asset_link,
};
use crate::clients::repository;

#[derive(Debug, Clone)]
pub struct AppLinkStatement {
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DeclaredAppLink {
    pub client_id: String,
    pub numeric_app_id: i64,
    pub client_name: String,
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

impl ClientService {
    /// Owner 显式登记一个 Client 的包名和签名指纹。
    pub async fn upsert_app_link(
        &self,
        client_id: &str,
        package_name: String,
        sha256_cert_fingerprints: Vec<String>,
    ) -> Result<Option<AndroidAssetLink>, ClientServiceError> {
        let Some(link) = validate_android_asset_link(Some(AndroidAssetLinkInput {
            package_name,
            sha256_cert_fingerprints,
        }))?
        else {
            return Err(
                crate::clients::android_link::AndroidAssetLinkError::InvalidFingerprint.into(),
            );
        };
        let updated = repository::upsert_client_app_link(&self.pool, client_id, &link).await?;
        Ok(updated.then_some(link))
    }

    /// Owner 清空一个 Client 的 App Link 声明。
    pub async fn delete_app_link(&self, client_id: &str) -> Result<bool, ClientServiceError> {
        repository::delete_client_app_link(&self.pool, client_id)
            .await
            .map_err(Into::into)
    }

    /// 管理面：每个已登记 Client 一行，不受 Client 列表分页截断。
    pub async fn declared_app_links(&self) -> Result<Vec<DeclaredAppLink>, ClientServiceError> {
        Ok(repository::list_declared_app_links(&self.pool)
            .await?
            .into_iter()
            .map(|row| DeclaredAppLink {
                client_id: row.client_id,
                numeric_app_id: row.numeric_app_id,
                client_name: row.client_name,
                package_name: row.package_name,
                sha256_cert_fingerprints: row.sha256_cert_fingerprints,
            })
            .collect())
    }

    /// 公开读取：聚合所有已登记的 App Link（不查 Issuer，不做鉴权）。
    pub async fn published_app_links(&self) -> Result<Vec<AppLinkStatement>, ClientServiceError> {
        let links = repository::list_client_app_links(&self.pool).await?;
        Ok(links
            .into_iter()
            .map(|(package_name, fingerprints)| AppLinkStatement {
                package_name,
                sha256_cert_fingerprints: fingerprints,
            })
            .collect())
    }
}
