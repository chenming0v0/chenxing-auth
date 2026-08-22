use crate::sqlx::{PgPool, types::Json};
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

use crate::clients::domain::{ClientAuthMethod, ValidatedClientRegistration};
use crate::plans::domain::AuthQuotaLimits;
use crate::users::domain::UserId;

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

    pub(super) fn secret_hash(&self) -> Option<&str> {
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
pub struct NewOwnedClient {
    pub client: NewClient,
    pub quota_limits: AuthQuotaLimits,
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

#[derive(Debug, thiserror::Error)]
pub enum AuditedClientInsertError {
    #[error("normal user OAuth project quota has been exhausted")]
    QuotaExceeded,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
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
pub(super) async fn insert_client_row<'executor, E>(
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
    // 保留墙钟（Issue #299 的明确例外）：Client 行的创建时间，不是凭据有效期。
    // Client Secret 本身没有过期语义，撤销通过 `revoke_client_tokens` 表达。
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

pub async fn insert_client_with_audit<F>(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    audit_event: F,
) -> Result<NewClient, AuditedClientInsertError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let mut transaction = pool.begin().await?;
    let created_at = OffsetDateTime::now_utc();
    let id = insert_client_row(
        &mut *transaction,
        &registration,
        &client_id,
        &credential,
        created_at,
        None,
    )
    .await?;
    let client = NewClient {
        id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id: None,
        auth_method: credential.auth_method(),
    };
    crate::audit::repository::insert_with(&mut *transaction, &audit_event(&client))
        .await
        .map_err(AuditedClientInsertError::Audit)?;
    transaction.commit().await?;
    Ok(client)
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

/// 查询 Client（可选 owner / status / 搜索过滤），返回当前页与总数。
///
/// - `owner_user_id = None`：管理端视图，不按 owner 过滤。
/// - `owner_user_id = Some(id)`：只统计/返回该用户拥有的 Client（Issue #415）。
/// - `search` / `status` 为 `None` 时对应过滤条件不生效。
///
/// COUNT 与页数据在同一 REPEATABLE READ 事务里读取，保证总数与行来自同一
/// MVCC 快照，翻页时不会出现总数与内容不一致。
pub async fn query_clients(
    pool: &PgPool,
    owner_user_id: Option<UserId>,
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
    // COUNT and page rows must observe one MVCC snapshot.
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let total = crate::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients
         WHERE ($1::bigint IS NULL OR owner_user_id = $1)
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR client_id LIKE $3 ESCAPE E'\\\\'
                OR client_name LIKE $3 ESCAPE E'\\\\')",
    )
    .bind(owner_user_id)
    .bind(status)
    .bind(search_pattern.as_deref())
    .fetch_one(&mut *transaction)
    .await?;
    let rows = crate::sqlx::query_as::<_, ClientRow>(&format!(
        "SELECT {LIST_COLUMNS}
         FROM oauth_clients
         WHERE ($1::bigint IS NULL OR owner_user_id = $1)
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR client_id LIKE $3 ESCAPE E'\\\\'
                OR client_name LIKE $3 ESCAPE E'\\\\')
         ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(owner_user_id)
    .bind(status)
    .bind(search_pattern.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(to_listed_client)
    .collect();
    transaction.commit().await?;
    Ok((rows, total))
}

pub async fn count_clients(pool: &PgPool) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(pool)
        .await
}
