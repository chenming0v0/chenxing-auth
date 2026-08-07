use std::time::Duration;

use redis::{
    AsyncConnectionConfig, Client, IntoConnectionInfo, RedisResult, aio::MultiplexedConnection,
};

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
    connection_config: AsyncConnectionConfig,
}

impl RedisClient {
    pub fn new(client: Client) -> Self {
        let connection_config = AsyncConnectionConfig::new()
            .set_connection_timeout(REDIS_CONNECTION_TIMEOUT)
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT);
        Self {
            client,
            connection_config,
        }
    }

    pub fn open<T: IntoConnectionInfo>(params: T) -> RedisResult<Self> {
        Ok(Self::new(Client::open(params)?))
    }

    pub async fn get_multiplexed_async_connection(&self) -> RedisResult<MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection_with_config(&self.connection_config)
            .await
    }
}

impl From<Client> for RedisClient {
    fn from(client: Client) -> Self {
        Self::new(client)
    }
}
