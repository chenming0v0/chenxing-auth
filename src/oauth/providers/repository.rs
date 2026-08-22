use crate::sqlx::Row;
use crate::sqlx::{PgConnection, PgPool};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::{ClientAuthMethod, ProviderRecord, ValidatedProviderInput};
use crate::db::advisory_lock::{BusinessLock, lock_business};
use crate::users::domain::{UserId, UserStatus};
use crate::users::email::EmailAddress;
use crate::users::email_policy::evaluate_email_policy;

#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: i64,
    pub provider_id: i64,
    pub user_id: UserId,
    pub subject: String,
    pub email: String,
    pub user_status: String,
}

pub use super::identity_repository::{
    BindIdentityError, LinkedExternalIdentity, UnlinkIdentityOutcome, bind_identity,
    list_identities, unlink_identity,
};

pub async fn insert_provider(
    connection: &mut PgConnection,
    input: &ValidatedProviderInput,
    ciphertext: Vec<u8>,
) -> Result<ProviderRecord, crate::sqlx::Error> {
    // 保留墙钟（Issue #299 的明确例外）：Provider 配置行的 created_at/updated_at，
    // 不参与任何过期判定。外部登录 State 的 TTL 走 Redis `TIME`（见 state_store）。
    let now = OffsetDateTime::now_utc();
    // 单条 INSERT ... RETURNING 直接拿回完整行：不做「先插再查」，既消除
    // 查询返回 None 时的 expect panic（Issue #345），也消除 INSERT 与 SELECT
    // 之间并发删除/清理造成的时间窗，同时省一次往返。
    let row = crate::sqlx::query_as::<_, ProviderRow>(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
          client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
          name_claim, email_verified_claim, client_auth_method, pkce_enabled,
          status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'disabled', $15, $15)
         RETURNING id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                   client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                   name_claim, email_verified_claim, client_auth_method, pkce_enabled, status, state_version",
    )
    .bind(&input.name)
    .bind(&input.slug)
    .bind(input.authorization_endpoint.as_str())
    .bind(input.token_endpoint.as_str())
    .bind(input.userinfo_endpoint.as_str())
    .bind(&input.client_id)
    .bind(ciphertext)
    .bind(serde_json::to_value(&input.scopes).expect("scopes are serializable"))
    .bind(&input.claims.subject)
    .bind(&input.claims.email)
    .bind(&input.claims.name)
    .bind(&input.claims.email_verified)
    .bind(auth_method_value(input.client_auth_method))
    .bind(input.pkce_enabled)
    .bind(now)
    .fetch_one(&mut *connection)
    .await?;
    parse_provider_row(row)
}

pub async fn list_providers(pool: &PgPool) -> Result<Vec<ProviderRecord>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                name_claim, email_verified_claim, client_auth_method, pkce_enabled, status, state_version
         FROM oauth_providers ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(parse_provider_row).collect()
}

/// Whether PostgreSQL already contains provider credentials encrypted with the
/// provider secret key. Startup uses this before touching the key directory so a
/// missing key cannot be mistaken for a fresh installation.
pub(crate) async fn has_client_secret_ciphertext(
    pool: &PgPool,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM oauth_providers
             WHERE octet_length(client_secret_ciphertext) > 0
         )",
    )
    .fetch_one(pool)
    .await
}

pub async fn find_by_slug(
    pool: &PgPool,
    slug: &str,
) -> Result<Option<ProviderRecord>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                name_claim, email_verified_claim, client_auth_method, pkce_enabled, status, state_version
         FROM oauth_providers WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    row.map(parse_provider_row).transpose()
}

pub async fn lock_by_slug(
    connection: &mut PgConnection,
    slug: &str,
) -> Result<Option<ProviderRecord>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                name_claim, email_verified_claim, client_auth_method, pkce_enabled, status, state_version
         FROM oauth_providers WHERE slug = $1 FOR UPDATE",
    )
    .bind(slug)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(parse_provider_row).transpose()
}

pub async fn update_provider(
    connection: &mut PgConnection,
    slug: &str,
    input: &ValidatedProviderInput,
    ciphertext: Vec<u8>,
    expected_version: i64,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_providers
         SET name = $2, authorization_endpoint = $3, token_endpoint = $4,
             userinfo_endpoint = $5, client_id = $6, client_secret_ciphertext = $7,
             scopes = $8, subject_claim = $9, email_claim = $10, name_claim = $11,
             email_verified_claim = $12, client_auth_method = $13, pkce_enabled = $14,
             updated_at = $15, state_version = state_version + 1
         WHERE slug = $1 AND state_version = $16",
    )
    .bind(slug)
    .bind(&input.name)
    .bind(input.authorization_endpoint.as_str())
    .bind(input.token_endpoint.as_str())
    .bind(input.userinfo_endpoint.as_str())
    .bind(&input.client_id)
    .bind(ciphertext)
    .bind(serde_json::to_value(&input.scopes).expect("scopes are serializable"))
    .bind(&input.claims.subject)
    .bind(&input.claims.email)
    .bind(&input.claims.name)
    .bind(&input.claims.email_verified)
    .bind(auth_method_value(input.client_auth_method))
    .bind(input.pkce_enabled)
    .bind(OffsetDateTime::now_utc())
    .bind(expected_version)
    .execute(&mut *connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn update_client_secret_ciphertext(
    connection: &mut PgConnection,
    provider_id: i64,
    ciphertext: &[u8],
) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar::<_, i64>(
        "UPDATE oauth_providers
         SET client_secret_ciphertext = $2, updated_at = $3, state_version = state_version + 1
         WHERE id = $1
         RETURNING state_version",
    )
    .bind(provider_id)
    .bind(ciphertext)
    .bind(OffsetDateTime::now_utc())
    .fetch_one(&mut *connection)
    .await
}

pub(crate) async fn lock_client_secret_ciphertexts(
    connection: &mut PgConnection,
) -> Result<Vec<(i64, Vec<u8>)>, crate::sqlx::Error> {
    crate::sqlx::query_as(
        "SELECT id, client_secret_ciphertext
         FROM oauth_providers
         WHERE octet_length(client_secret_ciphertext) > 0
         ORDER BY id
         FOR UPDATE",
    )
    .fetch_all(&mut *connection)
    .await
}

pub async fn set_status(
    connection: &mut PgConnection,
    slug: &str,
    status: &str,
    expected_version: i64,
) -> Result<Option<i64>, crate::sqlx::Error> {
    crate::sqlx::query_scalar::<_, i64>(
        "UPDATE oauth_providers
         SET status = $2, updated_at = $3, state_version = state_version + 1
         WHERE slug = $1 AND state_version = $4
         RETURNING state_version",
    )
    .bind(slug)
    .bind(status)
    .bind(OffsetDateTime::now_utc())
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await
}

pub async fn find_identity(
    pool: &PgPool,
    provider_id: i64,
    subject: &str,
) -> Result<Option<ExternalIdentity>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (i64, i64, UserId, String, String, String)>(
        "SELECT i.id, i.provider_id, i.user_id, i.subject, i.email, u.status
         FROM oauth_external_identities i
         JOIN users u ON u.id = i.user_id
         WHERE i.provider_id = $1 AND i.subject = $2",
    )
    .bind(provider_id)
    .bind(subject)
    .fetch_optional(pool)
    .await
    .map(|row| {
        row.map(
            |(id, provider_id, user_id, subject, email, user_status)| ExternalIdentity {
                id,
                provider_id,
                user_id,
                subject,
                email,
                user_status,
            },
        )
    })
}

pub async fn create_user_with_identity(
    pool: &PgPool,
    provider_id: i64,
    email: &EmailAddress,
    display_name: Option<&str>,
    subject: &str,
    password_hash: &str,
) -> Result<UserId, CreateIdentityError> {
    let mut transaction = pool.begin().await?;
    lock_business(&mut transaction, BusinessLock::OwnerBootstrap).await?;
    let existing_identity: Option<(UserId, String)> = crate::sqlx::query_as(
        "SELECT i.user_id, u.status
         FROM oauth_external_identities i
         JOIN users u ON u.id = i.user_id
         WHERE i.provider_id = $1 AND i.subject = $2
         FOR UPDATE OF i, u",
    )
    .bind(provider_id)
    .bind(subject)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((user_id, status)) = existing_identity {
        transaction.rollback().await?;
        if UserStatus::parse(&status) != Some(UserStatus::Active) {
            return Err(CreateIdentityError::UserDisabled);
        }
        return Ok(user_id);
    }

    // 按匹配值查重（Issue #302）：IdP 换一种书写返回同一个邮箱时，这里必须仍然
    // 认出"已注册"，否则会绕过展示值上的 UNIQUE 建出第二个账号。
    let existing_user: Option<UserId> =
        crate::sqlx::query_scalar("SELECT id FROM users WHERE canonical_email = $1 FOR UPDATE")
            .bind(email.canonical())
            .fetch_optional(&mut *transaction)
            .await?;
    if existing_user.is_some() {
        transaction.rollback().await?;
        return Err(CreateIdentityError::EmailAlreadyRegistered);
    }

    // 外部身份自动建号与普通注册共用同一准入策略（Issue #550）。读取和判定
    // 必须发生在创建事务内，并且位于任何 INSERT 之前：策略拒绝、损坏配置或
    // 后续数据库错误都不能留下 users / oauth_external_identities 半成品。
    let email_policy_raw =
        crate::settings::repository::get_text(&mut *transaction, crate::settings::EMAIL_POLICY_KEY)
            .await?;
    if evaluate_email_policy(email_policy_raw, email).is_err() {
        transaction.rollback().await?;
        return Err(CreateIdentityError::EmailPolicyRejected);
    }

    let owner_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
            .fetch_one(&mut *transaction)
            .await?;
    if !owner_exists {
        transaction.rollback().await?;
        return Err(CreateIdentityError::OwnerBootstrapRequired);
    }

    let username = format!("oauth_{}", Uuid::new_v4().simple());
    // 保留墙钟（Issue #299 的明确例外）：新用户与身份绑定的行创建时间。
    let now = OffsetDateTime::now_utc();
    let user_id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users
         (username, email, canonical_email, password_hash, password_login_enabled, display_name, status, created_at)
         VALUES ($1, $2, $3, $4, FALSE, $5, 'active', $6)
         RETURNING id",
    )
    .bind(username)
    .bind(email.display())
    .bind(email.canonical())
    .bind(password_hash)
    .bind(display_name)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    // 外部身份表上的 email 是建号那一刻的展示快照，没有唯一约束也不参与匹配；
    // 身份的唯一键是 (provider_id, subject)。
    crate::sqlx::query(
        "INSERT INTO oauth_external_identities
         (provider_id, user_id, subject, email, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(provider_id)
    .bind(user_id)
    .bind(subject)
    .bind(email.display())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(user_id)
}

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentityError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("email is already registered")]
    EmailAlreadyRegistered,
    #[error("email is not allowed by the registration policy")]
    EmailPolicyRejected,
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required before creating external users")]
    OwnerBootstrapRequired,
}

struct ProviderRow {
    id: i64,
    name: String,
    slug: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    client_id: String,
    client_secret_ciphertext: Vec<u8>,
    scopes: Value,
    subject_claim: String,
    email_claim: String,
    name_claim: Option<String>,
    email_verified_claim: Option<String>,
    client_auth_method: String,
    pkce_enabled: bool,
    status: String,
    state_version: i64,
}

impl<'r> crate::sqlx::FromRow<'r, crate::sqlx::PgRow> for ProviderRow {
    fn from_row(row: &'r crate::sqlx::PgRow) -> Result<Self, crate::sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            authorization_endpoint: row.try_get("authorization_endpoint")?,
            token_endpoint: row.try_get("token_endpoint")?,
            userinfo_endpoint: row.try_get("userinfo_endpoint")?,
            client_id: row.try_get("client_id")?,
            client_secret_ciphertext: row.try_get("client_secret_ciphertext")?,
            scopes: row.try_get("scopes")?,
            subject_claim: row.try_get("subject_claim")?,
            email_claim: row.try_get("email_claim")?,
            name_claim: row.try_get("name_claim")?,
            email_verified_claim: row.try_get("email_verified_claim")?,
            client_auth_method: row.try_get("client_auth_method")?,
            pkce_enabled: row.try_get("pkce_enabled")?,
            status: row.try_get("status")?,
            state_version: row.try_get("state_version")?,
        })
    }
}

fn parse_provider_row(row: ProviderRow) -> Result<ProviderRecord, crate::sqlx::Error> {
    let ProviderRow {
        id,
        name,
        slug,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        client_id,
        client_secret_ciphertext,
        scopes,
        subject_claim,
        email_claim,
        name_claim,
        email_verified_claim,
        client_auth_method,
        pkce_enabled,
        status,
        state_version,
    } = row;
    let scopes = serde_json::from_value(scopes)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))?;
    let authorization_endpoint = url::Url::parse(&authorization_endpoint)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))?;
    let token_endpoint = url::Url::parse(&token_endpoint)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))?;
    let userinfo_endpoint = url::Url::parse(&userinfo_endpoint)
        .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))?;
    let client_auth_method = match client_auth_method.as_str() {
        "basic" => ClientAuthMethod::Basic,
        "request_body" => ClientAuthMethod::RequestBody,
        _ => {
            return Err(crate::sqlx::Error::Decode(
                "invalid client auth method".into(),
            ));
        }
    };
    Ok(ProviderRecord {
        id,
        name,
        slug,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        client_id,
        client_secret_ciphertext,
        scopes,
        subject_claim,
        email_claim,
        name_claim,
        email_verified_claim,
        client_auth_method,
        pkce_enabled,
        status,
        state_version,
    })
}

fn auth_method_value(method: ClientAuthMethod) -> &'static str {
    match method {
        ClientAuthMethod::Basic => "basic",
        ClientAuthMethod::RequestBody => "request_body",
    }
}
