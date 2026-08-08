//! 头像读写路径。
//!
//! 三列 `avatar_data` / `avatar_mime` / `avatar_updated_at` 由 CHECK 约束绑成一个
//! 事实，因此写入和清除都必须整组操作，不允许只动其中一列。

use crate::sqlx::PgPool;
use time::OffsetDateTime;

use crate::users::domain::UserId;

/// 落库的头像字节及其响应所需的元数据。
#[derive(Debug)]
pub struct StoredAvatar {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub updated_at: OffsetDateTime,
}

/// 整组写入头像。
///
/// `updated_at` 由数据库时钟给出而不是应用进程：该时间戳是前端缓存击穿参数的
/// 唯一来源，多实例部署下用各自的本地时钟会让版本号回退。
pub async fn update_avatar(
    pool: &PgPool,
    id: UserId,
    bytes: &[u8],
    mime: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE users
            SET avatar_data = $2, avatar_mime = $3, avatar_updated_at = NOW(), updated_at = NOW()
          WHERE id = $1",
    )
    .bind(id)
    .bind(bytes)
    .bind(mime)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 整组清除头像，回落到前端的首字母占位符。
pub async fn clear_avatar(pool: &PgPool, id: UserId) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE users
            SET avatar_data = NULL, avatar_mime = NULL, avatar_updated_at = NULL, updated_at = NOW()
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 读取头像字节。
///
/// 只在 `avatar_data IS NOT NULL` 时返回行，让「用户不存在」与「用户没有头像」在
/// 调用方看来是同一个 `None`：两者都应该得到 404，无需在服务层再分支。
pub async fn find_avatar(
    pool: &PgPool,
    id: UserId,
) -> Result<Option<StoredAvatar>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Vec<u8>, String, OffsetDateTime)>(
        "SELECT avatar_data, avatar_mime, avatar_updated_at FROM users
          WHERE id = $1 AND avatar_data IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(bytes, mime, updated_at)| StoredAvatar {
            bytes,
            mime,
            updated_at,
        })
    })
}
