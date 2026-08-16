use jsonwebtoken::EncodingKey;

/// 签发一次令牌所需的不可撕裂密钥快照。
///
/// `key_id` 和 `encoding_key` 来自同一份密钥状态读取，调用方不得分别从
/// `KeyManager` 读取它们，否则轮换发生在两次读取之间时会产生错误的 JWT。
#[derive(Clone)]
pub struct ActiveSigningKey {
    pub(super) key_id: String,
    pub(super) encoding_key: EncodingKey,
}

impl ActiveSigningKey {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }
}
