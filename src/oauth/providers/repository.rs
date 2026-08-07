use crate::sqlx::PgPool;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::{ClientAuthMethod, ProviderRecord, ValidatedProviderInput};
use crate::users::domain::{UserId, normalize_email};

#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: i64,
    pub provider_id: i64,
    pub user_id: UserId,
    pub subject: String,
    pub email: String,
    pub user_status: String,
}

pub async fn insert_provider(
    pool: &PgPool,
    input: &ValidatedProviderInput,
    ciphertext: Vec<u8>,
) -> Result<ProviderRecord, crate::sqlx::Error> {
    let now = OffsetDateTime::now_utc();
    crate::sqlx::query_scalar::<_, i64>(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
          client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
          name_claim, email_verified_claim, client_auth_method, pkce_enabled,
          status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'disabled', $15, $15)
         RETURNING id",
    )
    .bind(&input.name)
    .bind(&input.slug)
    .bind(input.authorization_endpoint.as_str())
    .bind(input.token_endpoint.as_str())
    .bind(input.userinfo_endpoint.as_str())
    .bind(&input.client_id)
    .bind(ciphertext)
    .bind(serde_json::to_value(&input.scopes).expect("scopes are serializable"))
    .bind(&input.subject_claim)
    .bind(&input.email_claim)
    .bind(&input.name_claim)
    .bind(&input.email_verified_claim)
    .bind(auth_method_value(input.client_auth_method))
    .bind(input.pkce_enabled)
    .bind(now)
    .fetch_one(pool)
    .await?;
    find_by_slug(pool, &input.slug)
        .await
        .map(|record| record.expect("inserted provider must be queryable"))
}

pub async fn list_providers(pool: &PgPool) -> Result<Vec<ProviderRecord>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                name_claim, email_verified_claim, client_auth_method, pkce_enabled, status
         FROM oauth_providers ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(parse_provider_row).collect()
}

pub async fn find_by_slug(
    pool: &PgPool,
    slug: &str,
) -> Result<Option<ProviderRecord>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
                client_id, client_secret_ciphertext, scopes, subject_claim, email_claim,
                name_claim, email_verified_claim, client_auth_method, pkce_enabled, status
         FROM oauth_providers WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    row.map(parse_provider_row).transpose()
}

pub async fn update_provider(
    pool: &PgPool,
    slug: &str,
    input: &ValidatedProviderInput,
    ciphertext: Vec<u8>,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_providers
         SET name = $2, authorization_endpoint = $3, token_endpoint = $4,
             userinfo_endpoint = $5, client_id = $6, client_secret_ciphertext = $7,
             scopes = $8, subject_claim = $9, email_claim = $10, name_claim = $11,
             email_verified_claim = $12, client_auth_method = $13, pkce_enabled = $14,
             updated_at = $15
         WHERE slug = $1",
    )
    .bind(slug)
    .bind(&input.name)
    .bind(input.authorization_endpoint.as_str())
    .bind(input.token_endpoint.as_str())
    .bind(input.userinfo_endpoint.as_str())
    .bind(&input.client_id)
    .bind(ciphertext)
    .bind(serde_json::to_value(&input.scopes).expect("scopes are serializable"))
    .bind(&input.subject_claim)
    .bind(&input.email_claim)
    .bind(&input.name_claim)
    .bind(&input.email_verified_claim)
    .bind(auth_method_value(input.client_auth_method))
    .bind(input.pkce_enabled)
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn set_status(
    pool: &PgPool,
    slug: &str,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_providers SET status = $2, updated_at = $3 WHERE slug = $1",
    )
    .bind(slug)
    .bind(status)
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
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
    email: &str,
    display_name: Option<&str>,
    subject: &str,
    password_hash: &str,
) -> Result<UserId, CreateIdentityError> {
    let email = normalize_email(email);
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock(7341928)")
        .execute(&mut *transaction)
        .await?;
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
        if status != "active" {
            return Err(CreateIdentityError::UserDisabled);
        }
        return Ok(user_id);
    }

    let existing_user: Option<UserId> =
        crate::sqlx::query_scalar("SELECT id FROM users WHERE email = $1 FOR UPDATE")
            .bind(&email)
            .fetch_optional(&mut *transaction)
            .await?;
    if existing_user.is_some() {
        transaction.rollback().await?;
        return Err(CreateIdentityError::EmailAlreadyRegistered);
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
    let now = OffsetDateTime::now_utc();
    let user_id: UserId = crate::sqlx::query_scalar(
        "INSERT INTO users
         (username, email, password_hash, password_login_enabled, display_name, status, created_at)
         VALUES ($1, $2, $3, FALSE, $4, 'active', $5)
         RETURNING id",
    )
    .bind(username)
    .bind(&email)
    .bind(password_hash)
    .bind(display_name)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO oauth_external_identities
         (provider_id, user_id, subject, email, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(provider_id)
    .bind(user_id)
    .bind(subject)
    .bind(&email)
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
    #[error("external user is disabled")]
    UserDisabled,
    #[error("owner bootstrap is required before creating external users")]
    OwnerBootstrapRequired,
}

type ProviderRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    Value,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    bool,
    String,
);

fn parse_provider_row(row: ProviderRow) -> Result<ProviderRecord, crate::sqlx::Error> {
    let (
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
    ) = row;
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
    })
}

fn auth_method_value(method: ClientAuthMethod) -> &'static str {
    match method {
        ClientAuthMethod::Basic => "basic",
        ClientAuthMethod::RequestBody => "request_body",
    }
}
