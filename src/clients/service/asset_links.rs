//! Android App Links 声明管理：公开读取 + Owner 增删。

use super::{ClientService, ClientServiceError};
use crate::clients::android_link::{
    AndroidAssetLink, AndroidAssetLinkInput, validate_android_asset_link,
};
use crate::clients::repository;
use crate::users::ManagementActorCredential;

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
    /// 管理面：覆盖一个 Client 的 App Link 声明。
    ///
    /// 声明校验是纯函数，发生在事务外。会话复核、行更新和审计在仓库的同一个事务里。
    pub async fn upsert_app_link(
        &self,
        client_id: &str,
        package_name: String,
        sha256_cert_fingerprints: Vec<String>,
        management_actor: ManagementActorCredential,
        audit_event: crate::audit::AuditEvent,
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
        let updated = repository::upsert_client_app_link(
            &self.pool,
            client_id,
            &link,
            management_actor,
            audit_event,
        )
        .await
        .map_err(|error| super::map_audited_mutation(error, "app_link_upsert.audit_unavailable"))?;
        Ok(updated.then_some(link))
    }

    /// 管理面：清空一个平台管理 Client 的 App Link 声明。
    pub async fn delete_app_link(
        &self,
        client_id: &str,
        management_actor: ManagementActorCredential,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<bool, ClientServiceError> {
        repository::delete_client_app_link(&self.pool, client_id, management_actor, audit_event)
            .await
            .map_err(|error| {
                super::map_audited_mutation(error, "app_link_delete.audit_unavailable")
            })
    }

    /// 管理面：每个已发布的平台 Client 一行，不受 Client 列表分页截断。
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

    /// 公开读取：只聚合豁免 Client 的 App Link（不查 Issuer，不做鉴权）。
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

    /// 公开读取：某个 active Client 已发布的 Android 包名。
    ///
    /// 没有对应的 active Client，或该 Client 没有声明时返回 `None`。
    pub async fn active_app_link_package(
        &self,
        numeric_app_id: i64,
    ) -> Result<Option<String>, ClientServiceError> {
        Ok(
            repository::find_active_client_app_link(&self.pool, numeric_app_id)
                .await?
                .map(|link| link.package_name),
        )
    }
}
