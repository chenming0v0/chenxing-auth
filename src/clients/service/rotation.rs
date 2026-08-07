//! Client Secret rotation and refresh-token revocation.

use super::{ClientService, ClientServiceError, RotatedClientSecret};
use crate::clients::{credentials::generate_client_secret, repository};
use crate::users::domain::UserId;

impl ClientService {
    pub async fn rotate_secret(
        &self,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let (client_secret, hash) = generate_client_secret()?;
        if !repository::update_client_secret(&self.pool, None, client_id, &hash).await? {
            return Err(ClientServiceError::InvalidData);
        }
        self.revoke_refresh_tokens_after_rotation(client_id).await;
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }

    pub async fn rotate_secret_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
    ) -> Result<RotatedClientSecret, ClientServiceError> {
        let (client_secret, hash) = generate_client_secret()?;
        if !repository::update_client_secret(&self.pool, Some(owner_user_id), client_id, &hash)
            .await?
        {
            return Err(ClientServiceError::InvalidData);
        }
        self.revoke_refresh_tokens_after_rotation(client_id).await;
        Ok(RotatedClientSecret {
            client_id: client_id.to_owned(),
            client_secret,
        })
    }

    /// Secret 轮换后撤销该 Client 的全部 Refresh Token（Issue #62）。
    ///
    /// 不这么做的话「轮换」是安全空操作：攻击者拿到泄露的 Secret 换出的
    /// Refresh Token 在轮换后依然能继续换取新 Access Token，
    /// 管理员以为已经止损，实际没有。
    ///
    /// **故意不回滚 secret**（设计决策 §4）：新 secret 已经写入数据库并生效，
    /// 回滚会让「轮换没生效」这个更危险的状态被静默掩盖。撤销失败留下的
    /// 「旧 token 仍可用」是降级状态，通过 `tracing::error!` 暴露给运维，
    /// 可人工再次轮换或直接停用 Client。
    ///
    /// 同理，撤销失败不改变函数返回值：调用方必须拿到新 secret，
    /// 否则该 Client 会因为「新 secret 已生效但调用者不知道」而完全无法认证。
    async fn revoke_refresh_tokens_after_rotation(&self, client_id: &str) {
        let Some(store) = self.refresh_tokens.as_ref() else {
            // 未注入存储属于装配错误（生产路径一定会注入）。
            // 记 error 而不是静默跳过，否则 #62 会悄悄回归。
            tracing::error!(
                client_id = %client_id,
                "client secret rotated without refresh token store; \
                 previously issued refresh tokens remain valid (Issue #62)"
            );
            return;
        };
        match store.revoke_client_tokens(client_id).await {
            Ok(revoked) => {
                tracing::info!(
                    client_id = %client_id,
                    revoked_refresh_tokens = revoked,
                    "revoked refresh tokens after client secret rotation"
                );
            }
            Err(store_error) => {
                tracing::error!(
                    error = %store_error,
                    client_id = %client_id,
                    "failed to revoke refresh tokens after client secret rotation; \
                     previously issued tokens may still be usable (Issue #62)"
                );
            }
        }
    }
}
