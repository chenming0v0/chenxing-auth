use crate::sqlx::{PgPool, types::Json};
use crate::users::domain::UserId;
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;

/// ConsentService 的错误类型
#[derive(Debug, Error)]
pub enum ConsentServiceError {
    /// 数据库操作失败
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),

    /// 保存同意记录时对应的 OAuth Client 不存在
    #[error("OAuth client not found")]
    ClientNotFound,
}

#[derive(Clone)]
pub struct ConsentService {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizedApp {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub updated_at: OffsetDateTime,
}

impl ConsentService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn has_scopes(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<bool, crate::sqlx::Error> {
        let Some(stored) = crate::sqlx::query_as::<_, (Json<Vec<String>>, )>(
            "SELECT c.scopes FROM user_consents c JOIN oauth_clients oc ON oc.id = c.client_id WHERE c.user_id = $1 AND oc.client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(false);
        };
        Ok(scopes.iter().all(|scope| stored.0.contains(scope)))
    }

    /// 保存用户对某个 OAuth Client 的授权同意
    ///
    /// # 错误
    ///
    /// - `ClientNotFound`: 指定的 `client_id` 在数据库中不存在
    /// - `Database`: 数据库操作失败
    pub async fn save(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<(), ConsentServiceError> {
        let result = crate::sqlx::query(
            "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
             SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
             ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(serde_json::to_value(scopes).expect("scope list is serializable"))
        .bind(OffsetDateTime::now_utc())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ConsentServiceError::ClientNotFound);
        }

        Ok(())
    }

    pub async fn list_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<AuthorizedApp>, crate::sqlx::Error> {
        let rows = crate::sqlx::query_as::<_, (String, String, Json<Vec<String>>, OffsetDateTime)>(
            "SELECT oc.client_id, oc.client_name, c.scopes, c.updated_at
             FROM user_consents c
             JOIN oauth_clients oc ON oc.id = c.client_id
             WHERE c.user_id = $1
             ORDER BY c.updated_at DESC, oc.client_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(client_id, client_name, Json(scopes), updated_at)| AuthorizedApp {
                    client_id,
                    client_name,
                    scopes,
                    updated_at,
                },
            )
            .collect())
    }

    pub async fn revoke_for_user(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<bool, crate::sqlx::Error> {
        let result = crate::sqlx::query(
            "DELETE FROM user_consents c
             USING oauth_clients oc
             WHERE c.user_id = $1 AND c.client_id = oc.id AND oc.client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizedApp, ConsentServiceError};

    #[test]
    fn client_not_found_error_does_not_leak_internal_details() {
        let message = ConsentServiceError::ClientNotFound.to_string();

        assert_eq!(message, "OAuth client not found");
        // 错误信息面向调用方，不得暴露 SQL 语句或表结构
        assert!(!message.contains("INSERT"));
        assert!(!message.contains("user_consents"));
        assert!(!message.contains("oauth_clients"));
    }

    #[test]
    fn sqlx_error_converts_into_database_variant() {
        let error = ConsentServiceError::from(crate::sqlx::Error::RowNotFound);

        // 基础设施错误必须落在 Database 变体上，不能被误判成业务信号 ClientNotFound
        assert!(matches!(error, ConsentServiceError::Database(_)));
        assert!(error.to_string().starts_with("database operation failed:"));
    }

    #[test]
    fn authorized_app_response_contains_only_non_sensitive_fields() {
        let value = serde_json::to_value(AuthorizedApp {
            client_id: "cx_test".to_owned(),
            client_name: "Example App".to_owned(),
            scopes: vec!["openid".to_owned()],
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("authorized app serializes");
        let object = value.as_object().expect("authorized app object");

        assert_eq!(object.len(), 4);
        assert!(object.contains_key("client_id"));
        assert!(object.contains_key("client_name"));
        assert!(object.contains_key("scopes"));
        assert!(object.contains_key("updated_at"));
        assert!(!object.contains_key("client_secret"));
        assert!(!object.contains_key("redirect_uris"));
    }
}
