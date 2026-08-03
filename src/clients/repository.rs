use crate::sqlx::{PgPool, types::Json};
use thiserror::Error;
use time::OffsetDateTime;

use super::domain::ValidatedClientRegistration;
use crate::users::domain::UserId;

#[derive(Debug)]
pub struct NewClient {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub owner_user_id: Option<UserId>,
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
pub struct StoredClientCredentials {
    pub client_secret_hash: String,
    pub status: String,
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

pub async fn insert_client(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    client_secret_hash: String,
) -> Result<NewClient, crate::sqlx::Error> {
    let client = NewClient {
        id: 0,
        client_id,
        client_name: registration.client_name,
        client_secret_hash,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at: OffsetDateTime::now_utc(),
        owner_user_id: None,
    };

    let id: i64 = crate::sqlx::query_scalar(
        "INSERT INTO oauth_clients
         (client_id, client_name, client_secret_hash, redirect_uris, scopes, status, created_at, owner_user_id)
         VALUES ($1, $2, $3, $4, $5, 'active', $6, NULL)
         RETURNING id",
    )
    .bind(&client.client_id)
    .bind(&client.client_name)
    .bind(&client.client_secret_hash)
    .bind(serde_json::to_value(&client.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&client.scopes).expect("scopes are serializable"))
    .bind(client.created_at)
    .fetch_one(pool)
    .await?;

    let mut client = client;
    client.id = id;
    Ok(client)
}

pub async fn insert_owned_client(
    pool: &PgPool,
    owner_user_id: UserId,
    registration: ValidatedClientRegistration,
    client_id: String,
    client_secret_hash: String,
    oauth_clients_limit: i64,
) -> Result<NewClient, ClientInsertError> {
    let mut transaction = pool.begin().await?;
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

    let client = NewClient {
        id: 0,
        client_id,
        client_name: registration.client_name,
        client_secret_hash,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at: OffsetDateTime::now_utc(),
        owner_user_id: Some(owner_user_id),
    };
    let id: i64 = crate::sqlx::query_scalar(
        "INSERT INTO oauth_clients
         (client_id, client_name, client_secret_hash, redirect_uris, scopes, status, created_at, owner_user_id)
         VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
         RETURNING id",
    )
    .bind(&client.client_id)
    .bind(&client.client_name)
    .bind(&client.client_secret_hash)
    .bind(serde_json::to_value(&client.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&client.scopes).expect("scopes are serializable"))
    .bind(client.created_at)
    .bind(client.owner_user_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let mut client = client;
    client.id = id;
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

pub async fn find_client_credentials(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClientCredentials>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (String, String)>(
        "SELECT client_secret_hash, status FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(client_secret_hash, status)| StoredClientCredentials {
            client_secret_hash,
            status,
        })
    })
}

pub async fn list_clients(pool: &PgPool) -> Result<Vec<ListedClient>, crate::sqlx::Error> {
    crate::sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            Json<Vec<String>>,
            Json<Vec<String>>,
            String,
            Option<UserId>,
        ),
    >(
        "SELECT id, client_id, client_name, redirect_uris, scopes, status, owner_user_id
         FROM oauth_clients ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(id, client_id, client_name, redirect_uris, scopes, status, owner_user_id)| {
                    ListedClient {
                        id,
                        client_id,
                        client_name,
                        redirect_uris: redirect_uris.0,
                        scopes: scopes.0,
                        status,
                        owner_user_id,
                    }
                },
            )
            .collect()
    })
}

pub async fn list_clients_for_owner(
    pool: &crate::sqlx::PgPool,
    owner_user_id: UserId,
) -> Result<Vec<ListedClient>, crate::sqlx::Error> {
    crate::sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            Json<Vec<String>>,
            Json<Vec<String>>,
            String,
            Option<UserId>,
        ),
    >(
        "SELECT id, client_id, client_name, redirect_uris, scopes, status, owner_user_id
         FROM oauth_clients WHERE owner_user_id = $1 ORDER BY created_at DESC",
    )
    .bind(owner_user_id)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(id, client_id, client_name, redirect_uris, scopes, status, owner_user_id)| {
                    ListedClient {
                        id,
                        client_id,
                        client_name,
                        redirect_uris: redirect_uris.0,
                        scopes: scopes.0,
                        status,
                        owner_user_id,
                    }
                },
            )
            .collect()
    })
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
    let rows = crate::sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            Json<Vec<String>>,
            Json<Vec<String>>,
            String,
            Option<UserId>,
        ),
    >(
        "SELECT id, client_id, client_name, redirect_uris, scopes, status, owner_user_id
         FROM oauth_clients
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR client_id LIKE $2 ESCAPE E'\\\\'
                OR client_name LIKE $2 ESCAPE E'\\\\')
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(status)
    .bind(search_pattern.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(id, client_id, client_name, redirect_uris, scopes, status, owner_user_id)| ListedClient {
            id,
            client_id,
            client_name,
            redirect_uris: redirect_uris.0,
            scopes: scopes.0,
            status,
            owner_user_id,
        },
    )
    .collect();
    Ok((rows, total))
}

pub async fn count_clients(pool: &PgPool) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(pool)
        .await
}

pub async fn update_client(
    pool: &PgPool,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $2, redirect_uris = $3, scopes = $4
         WHERE client_id = $1",
    )
    .bind(client_id)
    .bind(name)
    .bind(serde_json::to_value(redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(scopes).expect("scopes are serializable"))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn update_owned_client(
    pool: &crate::sqlx::PgPool,
    owner_user_id: UserId,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_name = $3, redirect_uris = $4, scopes = $5
         WHERE client_id = $1 AND owner_user_id = $2",
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
    client_id: &str,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query("UPDATE oauth_clients SET status = $2 WHERE client_id = $1")
        .bind(client_id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn set_owned_client_status(
    pool: &crate::sqlx::PgPool,
    owner_user_id: UserId,
    client_id: &str,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET status = $3
         WHERE client_id = $1 AND owner_user_id = $2",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn update_client_secret(
    pool: &PgPool,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result =
        crate::sqlx::query("UPDATE oauth_clients SET client_secret_hash = $2 WHERE client_id = $1")
            .bind(client_id)
            .bind(client_secret_hash)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn update_owned_client_secret(
    pool: &crate::sqlx::PgPool,
    owner_user_id: UserId,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE oauth_clients SET client_secret_hash = $3
         WHERE client_id = $1 AND owner_user_id = $2",
    )
    .bind(client_id)
    .bind(owner_user_id)
    .bind(client_secret_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
