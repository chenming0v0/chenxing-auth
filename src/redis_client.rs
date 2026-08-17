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
                    .set_response_timeout(REDIS_RESPONSE_TIMEOUT)
                    // 初始连接失败必须快速返回，让 fail-open / fail-closed 策略接管，
                    // 而不是进入重试退避。redis 0.29 把 backon 的 factor 当作乘法因子
                    // （backon 1.6 语义：每次延迟 ×factor，起步 min_delay = 1s），
                    // 默认 factor = 100 使退避序列变成 1s → 100s → 10000s → …，
                    // 一个坏端点会把认证任务拖住数分钟到数年，违背上面的超时意图。
                    // 掉线后的恢复不依赖退避：每条命令失败都会触发一次新的连接尝试，
                    // Redis 恢复后下一条命令即自动重连成功。
                    .set_number_of_retries(0);
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
