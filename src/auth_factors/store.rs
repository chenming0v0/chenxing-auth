use redis::{AsyncCommands, ExistenceCheck, Script, SetExpiry, SetOptions};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

use super::domain::{FactorMethod, LoginTicket};
use crate::{clock::SharedClock, redis_client::RedisClient, users::domain::UserId};

const LOGIN_TICKET_PREFIX: &str = "chenxing:auth:login-ticket:";
const TOTP_REPLAY_PREFIX: &str = "chenxing:auth:totp-used:";
const TOTP_REPLAY_TTL_SECONDS: u64 = 120;
const CLAIM_TOTP_STEP_SCRIPT: &str =
    "if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then return 1 else return 0 end";
const TAKE_LOGIN_TICKET_IF_HOLDER_SCRIPT: &str = r#"
local payload = redis.call('GET', KEYS[1])
if not payload then return nil end
local ticket = cjson.decode(payload)
if ticket['holder_hash'] ~= ARGV[1] then return nil end
redis.call('DEL', KEYS[1])
return payload
"#;

#[derive(Clone)]
pub struct LoginTicketStore {
    client: RedisClient,
    metadata: Option<crate::sqlx::PgPool>,
    clock: SharedClock,
}

#[derive(Debug, Error)]
pub enum LoginTicketStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl LoginTicketStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            metadata: None,
            clock: SharedClock::system(),
        }
    }

    pub fn new_with_pool(client: impl Into<RedisClient>, metadata: crate::sqlx::PgPool) -> Self {
        Self {
            client: client.into(),
            metadata: Some(metadata),
            clock: SharedClock::system(),
        }
    }

    /// 注入共享时钟（`AuthFactorService` 构造时传入 `AppState` 的时钟）。
    ///
    /// ticket 的签发时刻与 `restore` 的剩余 TTL 都由它决定，因此固定时钟能把
    /// 5 分钟窗口的两侧都测到。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// Compatibility constructor for direct store users. HTTP-issued tickets
    /// must use `create_with_epoch_and_holder`; an unbound ticket is not
    /// accepted by `find_for_holder` or `take_for_holder`.
    pub async fn create(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        self.create_with_epoch(user_id, methods, 0).await
    }

    pub async fn create_with_epoch(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        session_epoch: i64,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        let ticket_id = Uuid::new_v4().to_string();
        let ticket =
            LoginTicket::new_with_epoch_at(user_id, methods, session_epoch, self.clock.now());
        self.save(&ticket_id, &ticket).await?;
        Ok((ticket_id, ticket))
    }

    pub async fn create_with_holder(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        holder_hash: String,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        self.create_with_epoch_and_holder(user_id, methods, 0, holder_hash)
            .await
    }

    pub async fn create_with_epoch_and_holder(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        session_epoch: i64,
        holder_hash: String,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        let ticket_id = Uuid::new_v4().to_string();
        let ticket = LoginTicket::new_with_epoch_and_holder_at(
            user_id,
            methods,
            session_epoch,
            Some(holder_hash),
            self.clock.now(),
        );
        self.save(&ticket_id, &ticket).await?;
        Ok((ticket_id, ticket))
    }

    pub async fn save(
        &self,
        ticket_id: &str,
        ticket: &LoginTicket,
    ) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&ticket)?;
        let _: () = connection
            .set_ex(
                Self::key(ticket_id),
                payload,
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(())
    }

    async fn find(&self, ticket_id: &str) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        self.read(ticket_id, false).await
    }

    pub async fn find_for_holder(
        &self,
        ticket_id: &str,
        holder_hash: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        Ok(self
            .find(ticket_id)
            .await?
            .filter(|ticket| ticket.matches_holder_hash(holder_hash)))
    }

    pub async fn take_for_holder(
        &self,
        ticket_id: &str,
        holder_hash: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(TAKE_LOGIN_TICKET_IF_HOLDER_SCRIPT)
            .key(Self::key(ticket_id))
            .arg(holder_hash)
            .invoke_async(&mut connection)
            .await?;
        self.decode_ticket_payload(payload).await
    }

    pub async fn restore(
        &self,
        ticket_id: &str,
        ticket: LoginTicket,
    ) -> Result<(), LoginTicketStoreError> {
        let ttl = (ticket.expires_at - self.clock.now()).whole_seconds();
        if ttl <= 0 {
            return Ok(());
        }
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&ticket)?;
        let _: () = connection
            .set_ex(Self::key(ticket_id), payload, ttl as u64)
            .await?;
        Ok(())
    }

    async fn read(
        &self,
        ticket_id: &str,
        consume: bool,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = if consume {
            connection.get_del(Self::key(ticket_id)).await?
        } else {
            connection.get(Self::key(ticket_id)).await?
        };
        self.decode_ticket_payload(payload).await
    }

    async fn decode_ticket_payload(
        &self,
        payload: Option<String>,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let ticket: Option<LoginTicket> = payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)?;
        let Some(ticket) = ticket else {
            return Ok(None);
        };
        if let Some(pool) = &self.metadata {
            let current_epoch: Option<i64> =
                crate::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
                    .bind(ticket.user_id)
                    .fetch_optional(pool)
                    .await?;
            if current_epoch != Some(ticket.session_epoch) {
                return Ok(None);
            }
        }
        Ok(Some(ticket))
    }

    pub fn key(ticket_id: &str) -> String {
        format!("{LOGIN_TICKET_PREFIX}{ticket_id}")
    }

    pub async fn take_json<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(key).await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)
    }

    pub async fn find_json<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(key).await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)
    }

    pub async fn save_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(value)?;
        let _: () = connection.set_ex(key, payload, ttl_seconds).await?;
        Ok(())
    }

    /// 只在键不存在时写入，返回本次调用是否是写入者。
    ///
    /// 存在的键一律保持原值：调用方靠返回的 `false` 判断自己是竞态的败者，
    /// 而不需要先 `find_json` 再 `save_json`。先查后写在两次往返之间没有任何
    /// 互斥，两个并发请求会都读到空、都写入，后者覆盖前者已经交给用户的密钥
    /// 材料（#265）。Redis 的 `SET NX EX` 是单条命令，检查与写入在同一个原子
    /// 步骤内完成，因此不存在这个窗口。
    ///
    /// 序列化在发出命令之前完成：序列化失败不应该占用键，否则会把一个本可重试
    /// 的编码错误变成 TTL 之内谁都无法重新预留的死锁。
    pub async fn save_json_if_absent<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<bool, LoginTicketStoreError> {
        let payload = serde_json::to_string(value)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        // `SET` 在 NX 未命中时回复 Nil，redis-rs 把 Nil 解析为 false、OK 解析为 true。
        let stored: bool = connection
            .set_options(
                key,
                payload,
                SetOptions::default()
                    .conditional_set(ExistenceCheck::NX)
                    .with_expiration(SetExpiry::EX(ttl_seconds)),
            )
            .await?;
        Ok(stored)
    }

    pub async fn delete(&self, key: &str) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(key).await?;
        Ok(())
    }

    pub async fn claim_totp_timestep(
        &self,
        user_id: UserId,
        timestep: u64,
    ) -> Result<bool, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let claimed: i64 = Script::new(CLAIM_TOTP_STEP_SCRIPT)
            .key(Self::totp_replay_key(user_id, timestep))
            .arg(TOTP_REPLAY_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await?;
        Ok(claimed == 1)
    }

    pub fn totp_replay_key(user_id: UserId, timestep: u64) -> String {
        format!("{TOTP_REPLAY_PREFIX}{user_id}:{timestep}")
    }

    /// 删除该用户全部 TOTP 一次性时间步 claim。
    ///
    /// 因子被管理端重置后，旧 claim 保护的验证码已无可验证的因子，继续保留只会
    /// 挡住同一时间步窗口内的重新注册（#301 之后注册确认也 claim 时间步）。
    /// claim 键按 `{user_id}:{timestep}` 分布、timestep 不可枚举，所以用 SCAN；
    /// 这是低频的管理动作，扫描成本可接受。
    pub async fn clear_totp_replay(&self, user_id: UserId) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let mut keys: Vec<String> = Vec::new();
        {
            // AsyncIter 持有 connection 的可变借用，必须在这个块里耗尽并 drop。
            let mut iter = connection
                .scan_match(format!("{TOTP_REPLAY_PREFIX}{user_id}:*"))
                .await?;
            while let Some(key) = iter.next_item().await {
                keys.push(key);
            }
        }
        if !keys.is_empty() {
            let _: usize = connection.del(keys).await?;
        }
        Ok(())
    }
}
