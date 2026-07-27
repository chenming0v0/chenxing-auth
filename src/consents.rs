use sqlx::{PgPool, types::Json};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct ConsentService {
    pool: PgPool,
}

impl ConsentService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn has_scopes(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: &[String],
    ) -> Result<bool, sqlx::Error> {
        let Some(stored) = sqlx::query_as::<_, (Json<Vec<String>>, )>(
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

    pub async fn save(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: &[String],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
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
        Ok(())
    }
}
