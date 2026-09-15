use crate::db_isolation;

use std::{
    env,
    sync::{Arc, RwLock},
    time::Duration,
};

use base64::Engine;
use chenxing_auth::{
    clients::{
        domain::ValidatedClientRegistration,
        repository::{self as client_repository, ClientCredential},
    },
    config::{AuthEncryptionKey, AuthEncryptionKeyRing},
    oauth::{
        code::AuthorizationCode,
        refresh::RefreshToken,
        refresh_store::{RefreshTokenStore, RotationOutcome},
        store::AuthorizationCodeStore,
    },
    sessions::{
        domain::{Session, session_token_hash_bytes},
        store::SessionStore,
    },
    settings::SessionLifetimeSetting,
    users::{
        credentials::hash_password,
        domain::{UserRole, UserStatus, ValidatedRegistration},
        email::EmailAddress,
        repository::{self as user_repository, NewUser},
    },
};
use redis::AsyncCommands;
use sha2::Digest;
use time::OffsetDateTime;
use uuid::Uuid;

/// 测试夹具的邮箱构造。
///
/// `ValidatedRegistration.email` 是 `EmailAddress`（Issue #302），构造它必须经过
/// 唯一的规范化入口——夹具也不例外，否则测试会绕开被测的那条规则。
fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections("integration_storage", &database_url, 4).await
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

fn session_store_key() -> [u8; 32] {
    [0x42; 32]
}

fn session_revocation_marker(user_id: i64) -> String {
    format!("chenxing:session:revoked-epoch:{user_id}")
}

fn session_redis_key(token: &str) -> String {
    format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_token_hash_bytes(token))
    )
}

async fn enqueue_session_sync(pool: &chenxing_auth::sqlx::PgPool, session_id: i64) {
    let result = chenxing_auth::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         SELECT 'sync_session', id, user_id, token_hash, session_epoch
         FROM user_sessions
         WHERE id = $1",
    )
    .bind(session_id)
    .execute(pool)
    .await
    .expect("enqueue session sync fixture");
    assert_eq!(result.rows_affected(), 1, "session fixture must exist");
}

fn unavailable_redis_client() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL")
}

mod owned_clients;
mod password_change;
mod redis_stores;
mod repository;
mod session_encryption;
mod session_epoch;
mod session_lookup;
mod session_outbox;
mod session_policy;
mod session_projection;
mod session_renewal;
mod session_revoke;
mod session_ttl;
