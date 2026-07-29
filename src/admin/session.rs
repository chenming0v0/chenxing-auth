use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::domain::AdminId;

pub const ADMIN_SESSION_COOKIE: &str = "chenxing_admin_session";
pub const ADMIN_CSRF_COOKIE: &str = "chenxing_admin_csrf";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub id: Uuid,
    pub admin_id: AdminId,
    pub csrf_token: String,
}

#[derive(Clone)]
pub struct AdminSessionStore {
    client: Client,
}

impl AdminSessionStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        admin_id: AdminId,
        ttl: Duration,
    ) -> Result<AdminSession, redis::RedisError> {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let session = AdminSession {
            id: Uuid::new_v4(),
            admin_id,
            csrf_token: URL_SAFE_NO_PAD.encode(bytes),
        };
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&session).expect("admin session is serializable");
        let _: () = connection
            .set_ex(Self::key(session.id), payload, ttl.as_secs().max(1))
            .await?;
        Ok(session)
    }

    pub async fn find(&self, id: Uuid) -> Result<Option<AdminSession>, redis::RedisError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::key(id)).await?;
        Ok(payload.and_then(|value| serde_json::from_str(&value).ok()))
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), redis::RedisError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(Self::key(id)).await?;
        Ok(())
    }

    fn key(id: Uuid) -> String {
        format!("chenxing:admin:session:{id}")
    }
}
