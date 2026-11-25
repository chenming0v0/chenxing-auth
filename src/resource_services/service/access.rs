use crate::sqlx::{Postgres, Transaction};
use crate::users::{
    UserSessionCredential, UserSessionValidation, domain::UserId,
    validate_user_session_in_transaction,
};

use super::ResourceServiceService;
use crate::resource_services::service_error::ServiceError;

/// 浏览器先验证 Cookie 会话；兑换请求由 HTTP 边界先验证 OAuth AT 和实时授权。
#[derive(Clone, Copy)]
pub(super) enum BindingAccess {
    Browser(UserSessionCredential),
    Exchange(UserId),
}

impl BindingAccess {
    pub(super) fn user_id(self) -> UserId {
        match self {
            Self::Browser(credential) => credential.user_id,
            Self::Exchange(user_id) => user_id,
        }
    }

    pub(super) async fn validate(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ServiceError> {
        match self {
            Self::Browser(credential) => {
                match validate_user_session_in_transaction(tx, credential).await? {
                    UserSessionValidation::Valid => Ok(()),
                    other => Err(ServiceError::from(other)),
                }
            }
            Self::Exchange(user_id) => {
                let active: bool = crate::sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND status = 'active')",
                )
                .bind(user_id)
                .fetch_one(&mut **tx)
                .await?;
                if active {
                    Ok(())
                } else {
                    Err(ServiceError::UserDisabled)
                }
            }
        }
    }
}

impl ResourceServiceService {
    pub(super) async fn revalidate_access(
        &self,
        access: BindingAccess,
    ) -> Result<(), ServiceError> {
        let mut tx = self.pool.begin().await?;
        access.validate(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
