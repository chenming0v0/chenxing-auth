use std::{sync::Arc, time::Duration};

use redis::{
    Client, IntoConnectionInfo, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use tokio::sync::OnceCell;

/// Redis TCP/DNS connection establishment must fail quickly enough that a broken
/// endpoint cannot hold an authentication task indefinitely.
pub const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Redis commands in this service are short reads/writes or bounded Lua scripts.
/// Five seconds gives Redis a useful budget without allowing a stalled command to
/// keep an authentication request alive for minutes.
pub const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct RedisClient {
    client: Client,
    connection: Arc<OnceCell<ConnectionManager>>,
}

impl RedisClient {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            connection: Arc::new(OnceCell::new()),
        }
    }

    pub fn open<T: IntoConnectionInfo>(params: T) -> RedisResult<Self> {
        Ok(Self::new(Client::open(params)?))
    }

    /// Returns a cheap handle to the one shared, reconnecting multiplexed connection.
    ///
    /// The cell is shared by every `RedisClient` clone, so stores created from the
    /// same client do not establish a TCP connection for every command. Failed
    /// initialization is not cached, while `ConnectionManager` replaces a dropped
    /// connection for subsequent commands.
    pub async fn get_multiplexed_async_connection(&self) -> RedisResult<ConnectionManager> {
        let connection = self
            .connection
            .get_or_try_init(|| async {
                let config = ConnectionManagerConfig::new()
                    .set_connection_timeout(REDIS_CONNECTION_TIMEOUT)
                    .set_response_timeout(REDIS_RESPONSE_TIMEOUT);
                ConnectionManager::new_with_config(self.client.clone(), config).await
            })
            .await?;
        Ok(connection.clone())
    }
}

impl From<Client> for RedisClient {
    fn from(client: Client) -> Self {
        Self::new(client)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use redis::{Client, RedisResult};
    use tokio::task::JoinSet;

    use super::RedisClient;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
    }

    #[tokio::test]
    async fn cloned_clients_share_one_connection_for_concurrent_commands() {
        const COMMAND_COUNT: usize = 32;

        let client = RedisClient::open(redis_url()).expect("Redis URL");
        let mut commands = JoinSet::new();
        for _ in 0..COMMAND_COUNT {
            let client = client.clone();
            commands.spawn(async move {
                let mut connection = client
                    .get_multiplexed_async_connection()
                    .await
                    .expect("managed Redis connection");
                redis::cmd("CLIENT")
                    .arg("ID")
                    .query_async::<i64>(&mut connection)
                    .await
                    .expect("Redis connection ID")
            });
        }

        let mut connection_ids = Vec::with_capacity(COMMAND_COUNT);
        while let Some(result) = commands.join_next().await {
            connection_ids.push(result.expect("concurrent Redis command task"));
        }

        assert_eq!(connection_ids.len(), COMMAND_COUNT);
        assert!(
            connection_ids
                .iter()
                .all(|connection_id| *connection_id == connection_ids[0]),
            "all commands should use the same multiplexed TCP connection"
        );
    }

    #[tokio::test]
    async fn dropped_shared_connection_is_replaced() {
        let redis_url = redis_url();
        let client = RedisClient::open(redis_url.as_str()).expect("Redis URL");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("managed Redis connection");
        let original_id: i64 = redis::cmd("CLIENT")
            .arg("ID")
            .query_async(&mut connection)
            .await
            .expect("original Redis connection ID");

        let killer = Client::open(redis_url).expect("Redis URL");
        let mut killer_connection = killer
            .get_multiplexed_async_connection()
            .await
            .expect("killer Redis connection");
        let killed: i64 = redis::cmd("CLIENT")
            .arg("KILL")
            .arg("ID")
            .arg(original_id)
            .query_async(&mut killer_connection)
            .await
            .expect("kill managed Redis connection");
        assert_eq!(killed, 1);

        let replacement_id = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let result: RedisResult<i64> = redis::cmd("CLIENT")
                    .arg("ID")
                    .query_async(&mut connection)
                    .await;
                if let Ok(connection_id) = result
                    && connection_id != original_id
                {
                    break connection_id;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("managed Redis connection should recover after disconnect");

        assert_ne!(replacement_id, original_id);
    }
}
