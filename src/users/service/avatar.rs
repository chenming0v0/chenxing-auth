//! 头像规范化与持久化编排。
//!
//! 头像失败模式（格式不支持、尺寸过小、解码失败）与注册、登录的失败模式没有交集，
//! 因此它们用独立的 [`AvatarServiceError`] 而不是塞进共享的 `UserServiceError`：
//! 后者会强迫每一个既有 `match` 去处理结构上不可能出现的分支。

use super::{UserService, UserServiceError};
use crate::users::{avatar_image, domain::UserId, repository};

#[derive(Debug, thiserror::Error)]
pub enum AvatarServiceError {
    #[error(transparent)]
    Image(#[from] avatar_image::AvatarImageError),
    #[error("avatar processing task failed")]
    Processing,
    #[error("could not persist avatar")]
    Database(#[from] crate::sqlx::Error),
}

impl From<UserServiceError> for AvatarServiceError {
    fn from(value: UserServiceError) -> Self {
        match value {
            UserServiceError::Database(error) => Self::Database(error),
            // 头像路径只调用仓储读写，不会产出其他变体。真出现了说明调用图变了，
            // 按内部错误处理而不是静默降级成校验失败。
            _ => Self::Processing,
        }
    }
}

impl UserService {
    /// 规范化上传字节并落库，返回更新后的资料。
    ///
    /// 规范化是 CPU 密集操作，放在 `spawn_blocking` 上执行：一张 5 MiB 的 JPEG
    /// 解码加缩放可达数十毫秒，留在异步执行器里会卡住同一 worker 上的其他请求。
    pub async fn update_avatar(
        &self,
        id: UserId,
        upload: Vec<u8>,
    ) -> Result<Option<repository::UserProfile>, AvatarServiceError> {
        let normalized = tokio::task::spawn_blocking(move || avatar_image::normalize(&upload))
            .await
            .map_err(|_| AvatarServiceError::Processing)??;

        if !repository::update_avatar(&self.pool, id, &normalized.bytes, normalized.mime).await? {
            return Ok(None);
        }
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    pub async fn clear_avatar(
        &self,
        id: UserId,
    ) -> Result<Option<repository::UserProfile>, AvatarServiceError> {
        if !repository::clear_avatar(&self.pool, id).await? {
            return Ok(None);
        }
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    pub async fn find_avatar(
        &self,
        id: UserId,
    ) -> Result<Option<repository::StoredAvatar>, AvatarServiceError> {
        Ok(repository::find_avatar(&self.pool, id).await?)
    }
}
