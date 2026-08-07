use crate::sqlx::{PgPool, types::Json};
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

use super::domain::{ClientAuthMethod, ValidatedClientRegistration};
use crate::users::domain::UserId;

#[path = "repository_rotation.rs"]
mod rotation;
pub use rotation::{
    find_client_secret_version, update_client_secret_if_version,
};

/// Client 的认证方式与对应凭据材料。
///
/// 三个变体与数据库 `oauth_clients_auth_method_check` 的三个取值一一对应，
/// 因此「公开客户端带 secret」或「机密客户端没有 secret」在类型上就不可构造，
/// 不需要在服务层或 SQL 里再补 if 判断（Issue #66 的安全边界）。
pub enum ClientCredential {
    /// 机密客户端，令牌端点用 HTTP Basic 提交凭据。
    SecretBasic(String),
    /// 机密客户端，令牌端点用请求体字段提交凭据。
    SecretPost(String),
    /// 公开客户端（SPA / 移动端）：不签发也不存储 secret，
    /// 令牌端点的防护由授权端点强制的 PKCE S256 承担。
    Public,
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretBasic(_) => f.debug_tuple("SecretBasic").field(&"<redacted>").finish(),
            Self::SecretPost(_) => f.debug_tuple("SecretPost").field(&"<redacted>").finish(),
            Self::Public => f.write_str("Public"),
        }
    }
}

impl ClientCredential {
    pub fn auth_method(&self) -> ClientAuthMethod {
        match self {
            Self::SecretBasic(_) => ClientAuthMethod::Basic,
            Self::SecretPost(_) => ClientAuthMethod::Post,
            Self::Public => ClientAuthMethod::None,
        }
    }

    fn secret_hash(&self) -> Option<&str> {
        match self {
            Self::SecretBasic(hash) | Self::SecretPost(hash) => Some(hash),
            Self::Public => None,
        }
    }
}

#[derive(Debug)]
pub struct NewClient {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub owner_user_id: Option<UserId>,
    pub auth_method: ClientAuthMethod,
}

#[derive(Debug)]
pub struct StoredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
}

pub struct StoredClientCredentials {
    pub client_secret_hash: Option<String>,
    pub auth_method: String,
    pub status: String,
}

impl fmt::Debug for StoredClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredClientCredentials")
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("auth_method", &self.auth_method)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug)]
pub struct ListedClient {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
}

#[derive(Debug, Error)]
pub enum ClientInsertError {
    #[error("normal user OAuth project quota has been exhausted")]
    QuotaExceeded,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

/// 列表查询的行元组。SELECT 列顺序与 `to_listed_client` 必须保持一致。
type ClientRow = (
    i64,
    String,
    String,
    Json<Vec<String>>,
    Json<Vec<String>>,
    String,
    Option<UserId>,
);

const LIST_COLUMNS: &str =
    "id, client_id, client_name, redirect_uris, scopes, status, owner_user_id";

fn to_listed_client(row: ClientRow) -> ListedClient {
    let (id, client_id, client_name, redirect_uris, scopes, status, owner_user_id) = row;
    ListedClient {
        id,
        client_id,
        client_name,
        redirect_uris: redirect_uris.0,
        scopes: scopes.0,
        status,
        owner_user_id,
    }
}

/// 单条 INSERT，供有主 / 无主两条注册路径共用。
/// 返回生成的自增 id，由调用方一次性构造 `NewClient`，避免占位值再回填（Issue #93）。
async fn insert_client_row<'executor, E>(
    executor: E,
    registration: &ValidatedClientRegistration,
    client_id: &str,
    credential: &ClientCredential,
    created_at: OffsetDateTime,
    owner_user_id: Option<UserId>,
) -> Result<i64, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'executor, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query_scalar(
        "INSERT INTO oauth_clients
         (client_id, client_name, client_secret_hash, redirect_uris, scopes, auth_method, status, created_at, owner_user_id)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
         RETURNING id",
    )
    .bind(client_id)
    .bind(&registration.client_name)
    .bind(credential.secret_hash())
    .bind(serde_json::to_value(&registration.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&registration.scopes).expect("scopes are serializable"))
    .bind(credential.auth_method().as_str())
    .bind(created_at)
    .bind(owner_user_id)
    .fetch_one(executor)
    .await
}

pub async fn insert_client(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
) -> Result<NewClient, crate::sqlx::Error> {
    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        pool,
        &registration,
        &client_id,
        &credential,
        created_at,
        None,
    )
    .await?;
    Ok(NewClient {
        id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id: None,
        auth_method: credential.auth_method(),
    })
}

pub async fn insert_owned_client(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    oauth_clients_limit: i64,
) -> Result<NewClient, ClientInsertError> {
    let mut transaction = pool.begin().await?;
    // 锁住 owner 行，让并发注册的配额检查串行化。
    crate::sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_user_id)
        .fetch_one(&mut *transaction)
        .await?;
    let count: i64 =
        crate::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients WHERE owner_user_id = $1")
            .bind(owner_user_id)
            .fetch_one(&mut *transaction)
            .await?;
    if count >= oauth_clients_limit {
        transaction.rollback().await?;
        return Err(ClientInsertError::QuotaExceeded);
    }

    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        &mut *transaction,
        &registration,
        &client_id,
        &credential,
        created_at,
        Some(owner_user_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(NewClient {
        id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id: Some(owner_user_id),
        auth_method: credential.auth_method(),
    })
}

pub async fn find_client_by_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClient>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (String, String, Json<Vec<String>>, Json<Vec<String>>, String, Option<UserId>)>(
        "SELECT client_id, client_name, redirect_uris, scopes, status, owner_user_id FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(client_id, client_name, redirect_uris, scopes, status, owner_user_id)| StoredClient {
            client_id,
            client_name,
            redirect_uris: redirect_uris.0,
            scopes: scopes.0,
            status,
            owner_user_id,
        })
    })
}

pub async fn find_client_credentials(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClientCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (Option<String>, String, String)>(
        "SELECT client_secret_hash, auth_method, status FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(
            |(client_secret_hash, auth_method, status)| StoredClientCredentials {
                client_secret_hash,
                auth_method,
                status,
            },
        )
    })
}

/// 列出 Client。
///
/// - `owner_user_id = None`：管理端视图，返回全部 Client。
/// - `owner_user_id = Some(id)`：只返回该用户拥有的 Client。
///
/// `limit` / `offset` 必填：SQL 层永远带 LIMIT，调用方无法再拿到无上限结果集（Issue #67）。
pub async fn list_clients(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ListedClient>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, ClientRow>(&format!(
        "SELECT {LIST_COLUMNS}
         FROM oauth_clients
         WHERE ($1::bigint IS NULL OR owner_user_id = $1)
         ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(owner_user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(to_listed_client).collect())
}

pub async fn query_clients(
    pool: &PgPool,
    search: Option<&str>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ListedClient>, i64), crate::sqlx::Error> {
    let search_pattern = search.map(|value| {
        format!(
            "%{}%",
            value
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let total = crate::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR client_id LIKE $2 ESCAPE E'\\\\'
                OR client_name LIKE $2 ESCAPE E'\\\\')",
    )
    .bind(status)
    .bind(search_pattern.as_deref())
    .fetch_one(pool)
    .await?;
    let rows = crate::sqlx::query_as::<_, ClientRow>(&format!(
        "SELECT {LIST_COLUMNS}
         FROM oauth_clients
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR client_id LIKE $2 ESCAPE E'\\\\'
                OR client_name LIKE $2 ESCAPE E'\\\\')
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(status)
    .bind(search_pattern.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(to_listed_client)
    .collect();
    Ok((rows, total))
}

pub async fn count_clients(pool: &PgPool) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(pool)
        .await
}

/// 更新 Client 元数据。`owner_user_id = None` 表示管理端不受 owner 约束（Issue #92）。
pub async fn update_client(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(name)
    .bind(serde_json::to_value(redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(scopes).expect("scopes are serializable"))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn set_client_status(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET status = $3
         WHERE client_id = $1 AND ($2::bigint IS NULL OR owner_user_id = $2)",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 轮换 Client Secret。
///
/// `auth_method <> 'none'` 是安全边界：公开客户端不允许持有 secret，
/// 因此轮换请求匹配不到行、返回 false，调用方按「对象不可用」处理。
/// 用 SQL 条件而不是先查后写，避免检查与写入之间的竞态。
pub async fn update_client_secret(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let Some(expected_version) =
        find_client_secret_version(pool, owner_user_id, client_id).await?
    else {
        return Ok(false);
    };
    update_client_secret_if_version(
        pool,
        owner_user_id,
        client_id,
        expected_version,
        client_secret_hash,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_credential_carries_no_secret_hash() {
        // 公开客户端在类型层面就没有存放 secret 的位置（Issue #66）
        let credential = ClientCredential::Public;
        assert_eq!(credential.auth_method(), ClientAuthMethod::None);
        assert_eq!(credential.secret_hash(), None);
    }

    #[test]
    fn confidential_credentials_map_to_matching_auth_method() {
        let basic = ClientCredential::SecretBasic("hash-basic".to_owned());
        assert_eq!(basic.auth_method(), ClientAuthMethod::Basic);
        assert_eq!(basic.secret_hash(), Some("hash-basic"));

        let post = ClientCredential::SecretPost("hash-post".to_owned());
        assert_eq!(post.auth_method(), ClientAuthMethod::Post);
        assert_eq!(post.secret_hash(), Some("hash-post"));
    }

    #[test]
    fn credential_auth_method_values_match_database_check_constraint() {
        // 落库字符串必须落在 oauth_clients_auth_method_check 的取值集合内
        for credential in [
            ClientCredential::SecretBasic("hash".to_owned()),
            ClientCredential::SecretPost("hash".to_owned()),
            ClientCredential::Public,
        ] {
            assert!(matches!(
                credential.auth_method().as_str(),
                "client_secret_basic" | "client_secret_post" | "none"
            ));
        }
    }
}
