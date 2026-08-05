//! 本人资料读取、显示名更新与改密。

use super::{UserService, UserServiceError};
use crate::users::{
    credentials::{hash_password, verify_password},
    domain::{UserId, validate_display_name, validate_password_length},
    repository,
};

impl UserService {
    pub async fn find_profile(
        &self,
        id: UserId,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    pub async fn update_display_name(
        &self,
        id: UserId,
        display_name: Option<String>,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        let display_name = validate_display_name(display_name)?;
        if !repository::update_display_name(&self.pool, id, display_name.as_deref()).await? {
            return Ok(None);
        }
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    /// 修改口令。
    ///
    /// 长度校验走与注册同一个 `validate_password_length`，上下界不允许在两条路径
    /// 之间漂移（Issue #122）。校验通过后由仓储层在同一事务内改哈希并撤销全部会话。
    pub async fn change_password(
        &self,
        id: UserId,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), UserServiceError> {
        validate_password_length(new_password).map_err(UserServiceError::Validation)?;
        let Some(credentials) = repository::find_credentials_by_id(&self.pool, id).await? else {
            return Err(UserServiceError::InvalidCredentials);
        };
        if credentials.status != "active"
            || !verify_password(
                current_password.to_owned(),
                credentials.password_hash.clone(),
            )
            .await
        {
            return Err(UserServiceError::InvalidCredentials);
        }
        let password_hash = hash_password(new_password.to_owned())
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        if !repository::change_password_and_revoke_all(&self.pool, id, &password_hash).await? {
            return Err(UserServiceError::InvalidCredentials);
        }
        Ok(())
    }
}
