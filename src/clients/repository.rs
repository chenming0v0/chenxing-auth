use sqlx::{PgPool, types::Json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::ValidatedClientRegistration;

#[derive(Debug)]
pub struct NewClient {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct StoredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
}

#[derive(Debug)]
pub struct StoredClientCredentials {
    pub client_secret_hash: String,
    pub status: String,
}

#[derive(Debug)]
pub struct ListedClient {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
}

pub async fn insert_client(
    pool: &PgPool,
    registration: ValidatedClientRegistration,
    client_id: String,
    client_secret_hash: String,
) -> Result<NewClient, sqlx::Error> {
    let client = NewClient {
        id: Uuid::new_v4(),
        client_id,
        client_name: registration.client_name,
        client_secret_hash,
        redirect_uris: registration.redirect_uris,
        scopes: registration.scopes,
        created_at: OffsetDateTime::now_utc(),
    };

    sqlx::query(
        "INSERT INTO oauth_clients
         (id, client_id, client_name, client_secret_hash, redirect_uris, scopes, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7)",
    )
    .bind(client.id)
    .bind(&client.client_id)
    .bind(&client.client_name)
    .bind(&client.client_secret_hash)
    .bind(serde_json::to_value(&client.redirect_uris).expect("redirect URIs are serializable"))
    .bind(serde_json::to_value(&client.scopes).expect("scopes are serializable"))
    .bind(client.created_at)
    .execute(pool)
    .await?;

    Ok(client)
}

pub async fn find_client_by_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClient>, sqlx::Error> {
    sqlx::query_as::<_, (String, String, Json<Vec<String>>, Json<Vec<String>>, String)>(
        "SELECT client_id, client_name, redirect_uris, scopes, status FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map(|record| {
        record.map(|(client_id, client_name, redirect_uris, scopes, status)| StoredClient {
            client_id,
            client_name,
            redirect_uris: redirect_uris.0,
            scopes: scopes.0,
            status,
        })
    })
}

pub async fn find_client_credentials(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<StoredClientCredentials>, sqlx::Error> {
    sqlx::query_as::<_, (String, String)>(
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

pub async fn list_clients(pool: &PgPool) -> Result<Vec<ListedClient>, sqlx::Error> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            Json<Vec<String>>,
            Json<Vec<String>>,
            String,
        ),
    >(
        "SELECT id, client_id, client_name, redirect_uris, scopes, status
         FROM oauth_clients ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(id, client_id, client_name, redirect_uris, scopes, status)| ListedClient {
                    id,
                    client_id,
                    client_name,
                    redirect_uris: redirect_uris.0,
                    scopes: scopes.0,
                    status,
                },
            )
            .collect()
    })
}

pub async fn update_client(
    pool: &PgPool,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
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

pub async fn set_client_status(
    pool: &PgPool,
    client_id: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE oauth_clients SET status = $2 WHERE client_id = $1")
        .bind(client_id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn update_client_secret(
    pool: &PgPool,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE oauth_clients SET client_secret_hash = $2 WHERE client_id = $1")
            .bind(client_id)
            .bind(client_secret_hash)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}
