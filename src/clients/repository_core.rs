use crate::sqlx::{PgPool, types::Json};
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

use crate::clients::android_link::AndroidAssetLink;
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
    pub numeric_app_id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub owner_user_id: Option<UserId>,
    pub auth_method: ClientAuthMethod,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
    pub android_asset_link: Option<AndroidAssetLink>,
    pub quota_exempt: bool,
}

#[derive(Debug)]
pub struct NewOwnedClient {
    pub client: NewClient,
    pub quota_limits: AuthQuotaLimits,
}

#[derive(Debug)]
pub struct StoredClient {
    pub client_id: String,
    pub numeric_app_id: i64,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
    pub android_asset_link: Option<AndroidAssetLink>,
    pub quota_exempt: bool,
}

#[derive(Debug)]
pub struct ListedClient {
    pub id: i64,
    pub numeric_app_id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
    pub auth_method: ClientAuthMethod,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
    pub android_asset_link: Option<AndroidAssetLink>,
    pub quota_exempt: bool,
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
    #[error(transparent)]
    ManagementActor(#[from] crate::users::ManagementActorValidationError),
}

/// 列表查询的行元组。SELECT 列顺序与 `to_listed_client` 必须保持一致。
type ClientRow = (
    i64,
    i64,
    String,
    String,
    Json<Vec<String>>,
    Json<Vec<String>>,
    String,
    Option<UserId>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Json<AndroidAssetLink>>,
    bool,
);

const LIST_COLUMNS: &str = "id, numeric_app_id, client_id, client_name, redirect_uris, scopes, status, owner_user_id, auth_method, logo_uri, client_uri, description, android_asset_link, quota_exempt";

fn to_listed_client(row: ClientRow) -> ListedClient {
    let (
        id,
        numeric_app_id,
        client_id,
        client_name,
        redirect_uris,
        scopes,
        status,
        owner_user_id,
        auth_method,
        logo_uri,
        client_uri,
        description,
        android_asset_link,
        quota_exempt,
    ) = row;
    ListedClient {
        id,
        numeric_app_id,
        client_id,
        client_name,
        redirect_uris: redirect_uris.0,
        scopes: scopes.0,
        status,
        owner_user_id,
        auth_method: ClientAuthMethod::parse(&auth_method)
            .expect("oauth_clients.auth_method is constrained to ClientAuthMethod"),
        logo_uri,
        client_uri,
        description,
        android_asset_link: android_asset_link.map(|link| link.0),
        quota_exempt,
    }
}

pub(super) struct InsertedClientRow {
    pub id: i64,
    pub numeric_app_id: i64,
    pub quota_limits: Option<AuthQuotaLimits>,
}

/// 自助调用方先锁定用户和套餐；INSERT 内再按数据库当前时间解析套餐并检查额度。
/// 返回最终采用的授权配额，避免锁后到期回退却仍把旧套餐配额交给调用方。
/// 管理面 quota_exempt=true，不依赖用户套餐，也不占用自助额度。
pub(super) async fn insert_client_row<'executor, E>(
    executor: E,
    registration: &ValidatedClientRegistration,
    client_id: &str,
    credential: &ClientCredential,
    created_at: OffsetDateTime,
    owner_user_id: Option<UserId>,
    quota_exempt: bool,
) -> Result<Option<InsertedClientRow>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'executor, Database = crate::sqlx::Postgres>,
{
    let effective_plan_source = crate::plans::repository::EFFECTIVE_PLAN_FROM_USER;
    let row: Option<(i64, i64, Option<i64>, Option<i64>)> = crate::sqlx::query_as(&format!(
        "WITH decision_time AS MATERIALIZED (SELECT clock_timestamp() AS at),
         effective_plan AS MATERIALIZED (
             SELECT p.oauth_clients_limit, p.daily_auth_limit, p.monthly_auth_limit
             {effective_plan_source} AND NOT $12
         ), inserted AS (
          INSERT INTO oauth_clients
          (client_id, client_name, client_secret_hash, redirect_uris, scopes, auth_method, status, created_at, owner_user_id, logo_uri, client_uri, description, quota_exempt)
          SELECT $2, $3, $4, $5, $6, $7, 'active', $8, $1, $9, $10, $11, $12
          WHERE $12 OR EXISTS (
              SELECT 1 FROM effective_plan
              WHERE (SELECT COUNT(*) FROM oauth_clients
                     WHERE owner_user_id = $1 AND quota_exempt = false)
                    < effective_plan.oauth_clients_limit
          )
          RETURNING id, numeric_app_id
         )
         SELECT inserted.id, inserted.numeric_app_id,
                effective_plan.daily_auth_limit, effective_plan.monthly_auth_limit
         FROM inserted LEFT JOIN effective_plan ON TRUE"
    ))
    .bind(owner_user_id)
    .bind(client_id)
    .bind(&registration.client_name)
    .bind(credential.secret_hash())
    .bind(serde_json::to_value(&registration.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&registration.scopes).expect("scopes are serializable"))
    .bind(credential.auth_method().as_str())
    .bind(created_at)
    .bind(&registration.logo_uri)
    .bind(&registration.client_uri)
    .bind(&registration.description)
    .bind(quota_exempt)
    .fetch_optional(executor)
    .await?;
    // 套餐配额由写入校验和数据库 CHECK 保证非负；管理创建没有 effective_plan 行。
    Ok(
        row.map(|(id, numeric_app_id, daily, monthly)| InsertedClientRow {
            id,
            numeric_app_id,
            quota_limits: daily.map(|limit| AuthQuotaLimits {
                daily_auth_limit: limit as u64,
                monthly_auth_limit: monthly.map(|limit| limit as u64),
            }),
        }),
    )
}

pub async fn insert_client(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    owner_user_id: Option<UserId>,
) -> Result<NewClient, crate::sqlx::Error> {
    // 保留墙钟（Issue #299 的明确例外）：Client 行的创建时间，不是凭据有效期。
    // Client Secret 本身没有过期语义，撤销通过 `revoke_client_tokens` 表达。
    let created_at = OffsetDateTime::now_utc();
    let inserted = insert_client_row(
        pool,
        &registration,
        &client_id,
        &credential,
        created_at,
        owner_user_id,
        true,
    )
    .await?
    .ok_or(crate::sqlx::Error::RowNotFound)?;
    Ok(NewClient {
        id: inserted.id,
        numeric_app_id: inserted.numeric_app_id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id,
        auth_method: credential.auth_method(),
        logo_uri: registration.logo_uri,
        client_uri: registration.client_uri,
        description: registration.description,
        android_asset_link: None,
        quota_exempt: true,
    })
}

pub async fn insert_client_with_audit<F>(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    credential: ClientCredential,
    owner_user_id: Option<UserId>,
    management_actor: crate::users::ManagementActorCredential,
    audit_event: F,
) -> Result<NewClient, AuditedClientInsertError>
where
    F: FnOnce(&NewClient) -> crate::audit::AuditEvent,
{
    let mut transaction = pool.begin().await?;
    super::revalidate_optional_management_actor(
        &mut transaction,
        Some(management_actor),
        crate::users::domain::UserPermission::ManageClients,
    )
    .await?;
    let created_at = OffsetDateTime::now_utc();
    let inserted = insert_client_row(
        &mut *transaction,
        &registration,
        &client_id,
        &credential,
        created_at,
        owner_user_id,
        true,
    )
    .await?
    .ok_or(crate::sqlx::Error::RowNotFound)?;
    let client = NewClient {
        id: inserted.id,
        numeric_app_id: inserted.numeric_app_id,
        client_id,
        client_name: registration.client_name,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at,
        owner_user_id,
        auth_method: credential.auth_method(),
        logo_uri: registration.logo_uri,
        client_uri: registration.client_uri,
        description: registration.description,
        android_asset_link: None,
        quota_exempt: true,
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
    crate::sqlx::query_as::<_, (String, i64, String, Json<Vec<String>>, Json<Vec<String>>, String, Option<UserId>, Option<String>, Option<String>, Option<String>, Option<Json<AndroidAssetLink>>, bool)>(
        "SELECT client_id, numeric_app_id, client_name, redirect_uris, scopes, status, owner_user_id, logo_uri, client_uri, description, android_asset_link, quota_exempt FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(client_id, numeric_app_id, client_name, redirect_uris, scopes, status, owner_user_id, logo_uri, client_uri, description, android_asset_link, quota_exempt)| StoredClient {
            client_id,
            numeric_app_id,
            client_name,
            redirect_uris: redirect_uris.0,
            scopes: scopes.0,
            status,
            owner_user_id,
            logo_uri,
            client_uri,
            description,
            android_asset_link: android_asset_link.map(|link| link.0),
            quota_exempt,
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
