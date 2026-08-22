use super::super::crypto;
use super::super::domain::{Session, SessionPayload, session_token_hash_bytes};
use super::{SessionStore, SessionStoreError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;
use time::OffsetDateTime;

impl SessionStore {
    pub(crate) fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        crypto::encrypt(keys, payload)
    }

    /// 解密并解析持久化载荷。
    ///
    /// 解密或解析失败返回 `Ok(None)`，由调用方按"会话不存在"处理，避免把密钥配置
    /// 问题和损坏数据变成可探测的错误差异。缺少密钥环属于配置错误，仍然返回 `Err`。
    ///
    /// 升级前写入的载荷含有 `token` 字段；`SessionPayload` 未标注
    /// `deny_unknown_fields`，serde 会忽略这个多余字段，因此历史数据继续可读。
    pub(crate) fn decode_payload(
        &self,
        payload: &[u8],
    ) -> Result<Option<SessionPayload>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        Ok(crypto::decrypt(keys, payload)
            .ok()
            .and_then(|payload| serde_json::from_slice(&payload).ok()))
    }

    pub(super) fn key(&self, token: &str) -> String {
        self.key_hash(&session_token_hash_bytes(token))
    }

    pub(crate) fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }

    pub(crate) fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-epoch:{user_id}", self.key_prefix)
    }

    pub(crate) fn redis_only_revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }

    pub(crate) fn redis_only_token_revocation_key(&self, hash: &[u8]) -> String {
        format!(
            "{}revoked-token:{}",
            self.key_prefix,
            URL_SAFE_NO_PAD.encode(hash)
        )
    }

    pub(crate) fn redis_only_token_renewal_key(&self, hash: &[u8]) -> String {
        format!(
            "{}renewed-token:{}",
            self.key_prefix,
            URL_SAFE_NO_PAD.encode(hash)
        )
    }

    pub(super) fn session_renewal_interval(&self, session: &Session) -> time::Duration {
        let idle_secs = session
            .idle_timeout()
            .unwrap_or(self.policy.idle_timeout)
            .as_secs();
        time::Duration::seconds(i64::try_from(idle_secs / 2).unwrap_or(i64::MAX).max(1))
    }

    /// 撤销标记（单条 tombstone 与用户级水位）的存活时长。
    ///
    /// 取绝对 Session TTL 是安全的下限：任何会话键的存活窗口都不超过
    /// [`Self::redis_ttl_seconds`]，而后者同样被这个值封顶（见该函数注释），
    /// 因此"撤销标记先于被它拦截的会话键消失"不可能发生。
    ///
    /// 启动配置把 `SESSION_TTL_SECONDS` 封顶在 90 天（#365），所以这个值
    /// 必然落在 Redis `EX` 的 i64 上限内，不会触发 `ERR invalid expire time`。
    pub(crate) fn revocation_ttl_seconds(&self) -> u64 {
        self.policy.absolute_ttl.as_secs().max(1)
    }

    /// 会话键在 Redis 的存活秒数。
    ///
    /// 除了绝对过期与 idle 截止，这里还被 [`Self::revocation_ttl_seconds`] 封顶。
    /// 这一层封顶是撤销水位 TTL 的安全前提：水位在撤销时刻 `T` 写入并带上
    /// `EX = revocation_ttl`，而任何在 `T` 之前写入的会话键最晚也在
    /// `写入时刻 + revocation_ttl <= T + revocation_ttl` 过期。水位不会先于它
    /// 应当拦截的旧会话消失，旧会话也就不可能在水位过期后复活。
    /// 调用方传入的 `absolute_ttl` 只能收紧、不能放宽这个上限。
    pub(super) fn redis_ttl_seconds(
        &self,
        session: &Session,
        absolute_ttl: Duration,
        now: OffsetDateTime,
    ) -> u64 {
        let absolute = (session.expires_at - now).whole_seconds().max(1) as u64;
        let idle = session
            .idle_deadline()
            .map(|deadline| (deadline - now).whole_seconds().max(1) as u64)
            .unwrap_or(absolute);
        absolute
            .min(idle)
            .min(absolute_ttl.as_secs().max(1))
            .min(self.revocation_ttl_seconds())
    }
}

pub(crate) fn timestamp_watermark(value: OffsetDateTime) -> i64 {
    value
        .unix_timestamp_nanos()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64
}
